// SPDX-License-Identifier: GPL-2.0+
#include "sparx5_main.h"

void sparx5_pgid_init(struct sparx5 *spx5)
{
	int i;

	for (i = 0; i < PGID_TABLE_SIZE; i++)
		spx5->pgid_map[i] = 0;

	/* Reserved for unicast, flood control, broadcast, and CPU.
	 * These cannot be freed.
	 */
	for (i = 0; i <= 72; i++)
		spx5->pgid_map[i] = SPX5_PGID_RESERVED;
}

int sparx5_pgid_alloc(struct sparx5 *spx5, enum sparx5_pgid_type type, u16 *idx)
{
	int i;

	for (i = 0; i <= PGID_TABLE_SIZE; i++)
		if (spx5->pgid_map[i] == 0) {
			spx5->pgid_map[i] = type;
			*idx = i;
			return 0;
		}

	return -EBUSY;
}

int sparx5_pgid_free(struct sparx5 *spx5, u16 idx)
{
	if (idx <= 72 || idx >= PGID_TABLE_SIZE)
		return -EINVAL;

	if (spx5->pgid_map[idx] == 0)
		return -EINVAL;

	spx5->pgid_map[idx] = 0;
	return 0;
}
