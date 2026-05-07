package repo

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/domain"
)

// pgAllowedNodesRepo 用 pgxpool 实现 AllowedNodesRepository。
type pgAllowedNodesRepo struct {
	pool *pgxpool.Pool
}

// NewAllowedNodesPG 构造 PG-backed AllowedNodesRepository。
func NewAllowedNodesPG(pool *pgxpool.Pool) AllowedNodesRepository {
	return &pgAllowedNodesRepo{pool: pool}
}

// === Set / ClearAll ===

// Set 在单事务内：DELETE 该 project 全部 + INSERT 新列表。
//
// 调用方：传非空 nodeIDs 表示白名单切换；如需"恢复 ALL"应改调 ClearAll。
// 传空切片在此实现里 = 删除所有（与 ClearAll 等价；但 service 层会用更明确的 ClearAll）。
func (r *pgAllowedNodesRepo) Set(ctx context.Context, projectID string, nodeIDs []string, addedBy string) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	return pgx.BeginFunc(ctx, r.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`DELETE FROM project_allowed_nodes WHERE project_id = $1::uuid`,
			projectID); err != nil {
			return errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: clear allowed nodes").
				WithFields("project_id", projectID)
		}
		if len(nodeIDs) == 0 {
			return nil
		}
		// 批量 INSERT；每行带 added_by（caller user id）
		batch := &pgx.Batch{}
		for _, nid := range nodeIDs {
			batch.Queue(`
				INSERT INTO project_allowed_nodes (project_id, node_id, added_by)
				VALUES ($1::uuid, $2::uuid, $3)
				ON CONFLICT (project_id, node_id) DO NOTHING
			`, projectID, nid, nullableUUID(addedBy))
		}
		br := tx.SendBatch(ctx, batch)
		defer br.Close()
		for range nodeIDs {
			if _, err := br.Exec(); err != nil {
				return errx.Wrap(errx.ErrDatabase, err,
					"tenancy.repo: insert allowed node").
					WithFields("project_id", projectID)
			}
		}
		return nil
	})
}

func (r *pgAllowedNodesRepo) ClearAll(ctx context.Context, projectID string) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	_, err := r.pool.Exec(ctx,
		`DELETE FROM project_allowed_nodes WHERE project_id = $1::uuid`,
		projectID)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: clear allowed nodes").
			WithFields("project_id", projectID)
	}
	return nil
}

// === Get / IsAllowed ===

func (r *pgAllowedNodesRepo) Get(ctx context.Context, projectID string) (domain.AllowedNodes, error) {
	if r == nil || r.pool == nil {
		return domain.AllowedNodes{}, errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	rows, err := r.pool.Query(ctx, `
		SELECT node_id::text
		  FROM project_allowed_nodes
		 WHERE project_id = $1::uuid
		 ORDER BY added_at ASC
	`, projectID)
	if err != nil {
		return domain.AllowedNodes{}, errx.Wrap(errx.ErrDatabase, err,
			"tenancy.repo: get allowed nodes").WithFields("project_id", projectID)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return domain.AllowedNodes{}, errx.Wrap(errx.ErrDatabase, err,
				"tenancy.repo: scan allowed node id")
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return domain.AllowedNodes{}, errx.Wrap(errx.ErrDatabase, err,
			"tenancy.repo: get allowed nodes iter")
	}
	// 表中无任何行 → AllNodes=true（ALL 默认）
	if len(ids) == 0 {
		return domain.AllowedNodes{AllNodes: true}, nil
	}
	return domain.AllowedNodes{NodeIDs: ids}, nil
}

func (r *pgAllowedNodesRepo) IsAllowed(ctx context.Context, projectID, nodeID string) (bool, error) {
	if r == nil || r.pool == nil {
		return false, errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	// 等价于 LLD 11 §3.4 注释里的双 EXISTS 表达式
	var allowed bool
	err := r.pool.QueryRow(ctx, `
		SELECT (NOT EXISTS (SELECT 1 FROM project_allowed_nodes WHERE project_id = $1::uuid))
		    OR EXISTS (SELECT 1 FROM project_allowed_nodes
		               WHERE project_id = $1::uuid AND node_id = $2::uuid)
	`, projectID, nodeID).Scan(&allowed)
	if err != nil {
		return false, errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: is allowed").
			WithFields("project_id", projectID, "node_id", nodeID)
	}
	return allowed, nil
}
