package poc

import (
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// LoadTemplate 从单个 reader 解析 YAML 模板。
func LoadTemplate(r io.Reader) (*Template, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, errx.Wrap(errx.ErrInternal, err, "poc: read template")
	}
	return LoadTemplateBytes(b)
}

// LoadTemplateBytes 从 YAML 字节解析。
func LoadTemplateBytes(b []byte) (*Template, error) {
	t := &Template{}
	if err := yaml.Unmarshal(b, t); err != nil {
		return nil, errx.Wrap(errx.ErrInvalidInput, err, "poc: yaml unmarshal")
	}
	if err := t.ValidateForLoad(); err != nil {
		return nil, err
	}
	return t, nil
}

// LoadDir 递归扫 fsys 下全部 .yaml / .yml 模板。
// 单文件解析失败仅 log（caller 提供 onError 回调；nil = 静默跳过）。
// 返按 template.ID 字典序排列的切片；重复 ID 后者覆盖前者并触发 onError。
func LoadDir(fsys fs.FS, root string, onError func(path string, err error)) ([]*Template, error) {
	if fsys == nil {
		return nil, errx.New(errx.ErrInternal, "poc: fsys 不能为 nil")
	}
	if root == "" {
		root = "."
	}
	seen := map[string]*Template{}
	err := fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if onError != nil {
				onError(path, walkErr)
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		f, err := fsys.Open(path)
		if err != nil {
			if onError != nil {
				onError(path, err)
			}
			return nil
		}
		defer f.Close() //nolint:errcheck // 只读关闭忽略
		t, err := LoadTemplate(f)
		if err != nil {
			if onError != nil {
				onError(path, err)
			}
			return nil
		}
		if old, dup := seen[t.ID]; dup && onError != nil {
			onError(path, errx.New(errx.ErrInvalidInput, "poc: duplicate template id").
				WithFields("id", t.ID, "previous_name", old.Info.Name))
		}
		seen[t.ID] = t
		return nil
	})
	if err != nil {
		return nil, errx.Wrap(errx.ErrInternal, err, "poc: walk templates dir")
	}
	out := make([]*Template, 0, len(seen))
	for _, t := range seen {
		out = append(out, t)
	}
	// 字典序排序，让多次加载结果稳定
	sortByID(out)
	return out, nil
}

func sortByID(ts []*Template) {
	// 简单冒泡，模板数预期 < 1000；标准库 sort 引入会让包依赖更重
	for i := 0; i < len(ts); i++ {
		for j := i + 1; j < len(ts); j++ {
			if ts[i].ID > ts[j].ID {
				ts[i], ts[j] = ts[j], ts[i]
			}
		}
	}
}
