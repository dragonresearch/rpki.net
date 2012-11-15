/*
 * Automatically generated, do not edit.
 * Generator $Id: defstack.py 4725 2012-09-19 21:28:34Z sra $
 */

#ifndef __RCYNIC_C__DEFSTACK_H__
#define __RCYNIC_C__DEFSTACK_H__

/*
 * Safestack macros for validation_status_t.
 */
#define sk_validation_status_t_new(st)                     SKM_sk_new(validation_status_t, (st))
#define sk_validation_status_t_new_null()                  SKM_sk_new_null(validation_status_t)
#define sk_validation_status_t_free(st)                    SKM_sk_free(validation_status_t, (st))
#define sk_validation_status_t_num(st)                     SKM_sk_num(validation_status_t, (st))
#define sk_validation_status_t_value(st, i)                SKM_sk_value(validation_status_t, (st), (i))
#define sk_validation_status_t_set(st, i, val)             SKM_sk_set(validation_status_t, (st), (i), (val))
#define sk_validation_status_t_zero(st)                    SKM_sk_zero(validation_status_t, (st))
#define sk_validation_status_t_push(st, val)               SKM_sk_push(validation_status_t, (st), (val))
#define sk_validation_status_t_unshift(st, val)            SKM_sk_unshift(validation_status_t, (st), (val))
#define sk_validation_status_t_find(st, val)               SKM_sk_find(validation_status_t, (st), (val))
#define sk_validation_status_t_find_ex(st, val)            SKM_sk_find_ex(validation_status_t, (st), (val))
#define sk_validation_status_t_delete(st, i)               SKM_sk_delete(validation_status_t, (st), (i))
#define sk_validation_status_t_delete_ptr(st, ptr)         SKM_sk_delete_ptr(validation_status_t, (st), (ptr))
#define sk_validation_status_t_insert(st, val, i)          SKM_sk_insert(validation_status_t, (st), (val), (i))
#define sk_validation_status_t_set_cmp_func(st, cmp)       SKM_sk_set_cmp_func(validation_status_t, (st), (cmp))
#define sk_validation_status_t_dup(st)                     SKM_sk_dup(validation_status_t, st)
#define sk_validation_status_t_pop_free(st, free_func)     SKM_sk_pop_free(validation_status_t, (st), (free_func))
#define sk_validation_status_t_shift(st)                   SKM_sk_shift(validation_status_t, (st))
#define sk_validation_status_t_pop(st)                     SKM_sk_pop(validation_status_t, (st))
#define sk_validation_status_t_sort(st)                    SKM_sk_sort(validation_status_t, (st))
#define sk_validation_status_t_is_sorted(st)               SKM_sk_is_sorted(validation_status_t, (st))

/*
 * Safestack macros for walk_ctx_t.
 */
#define sk_walk_ctx_t_new(st)                     SKM_sk_new(walk_ctx_t, (st))
#define sk_walk_ctx_t_new_null()                  SKM_sk_new_null(walk_ctx_t)
#define sk_walk_ctx_t_free(st)                    SKM_sk_free(walk_ctx_t, (st))
#define sk_walk_ctx_t_num(st)                     SKM_sk_num(walk_ctx_t, (st))
#define sk_walk_ctx_t_value(st, i)                SKM_sk_value(walk_ctx_t, (st), (i))
#define sk_walk_ctx_t_set(st, i, val)             SKM_sk_set(walk_ctx_t, (st), (i), (val))
#define sk_walk_ctx_t_zero(st)                    SKM_sk_zero(walk_ctx_t, (st))
#define sk_walk_ctx_t_push(st, val)               SKM_sk_push(walk_ctx_t, (st), (val))
#define sk_walk_ctx_t_unshift(st, val)            SKM_sk_unshift(walk_ctx_t, (st), (val))
#define sk_walk_ctx_t_find(st, val)               SKM_sk_find(walk_ctx_t, (st), (val))
#define sk_walk_ctx_t_find_ex(st, val)            SKM_sk_find_ex(walk_ctx_t, (st), (val))
#define sk_walk_ctx_t_delete(st, i)               SKM_sk_delete(walk_ctx_t, (st), (i))
#define sk_walk_ctx_t_delete_ptr(st, ptr)         SKM_sk_delete_ptr(walk_ctx_t, (st), (ptr))
#define sk_walk_ctx_t_insert(st, val, i)          SKM_sk_insert(walk_ctx_t, (st), (val), (i))
#define sk_walk_ctx_t_set_cmp_func(st, cmp)       SKM_sk_set_cmp_func(walk_ctx_t, (st), (cmp))
#define sk_walk_ctx_t_dup(st)                     SKM_sk_dup(walk_ctx_t, st)
#define sk_walk_ctx_t_pop_free(st, free_func)     SKM_sk_pop_free(walk_ctx_t, (st), (free_func))
#define sk_walk_ctx_t_shift(st)                   SKM_sk_shift(walk_ctx_t, (st))
#define sk_walk_ctx_t_pop(st)                     SKM_sk_pop(walk_ctx_t, (st))
#define sk_walk_ctx_t_sort(st)                    SKM_sk_sort(walk_ctx_t, (st))
#define sk_walk_ctx_t_is_sorted(st)               SKM_sk_is_sorted(walk_ctx_t, (st))

/*
 * Safestack macros for rsync_ctx_t.
 */
#define sk_rsync_ctx_t_new(st)                     SKM_sk_new(rsync_ctx_t, (st))
#define sk_rsync_ctx_t_new_null()                  SKM_sk_new_null(rsync_ctx_t)
#define sk_rsync_ctx_t_free(st)                    SKM_sk_free(rsync_ctx_t, (st))
#define sk_rsync_ctx_t_num(st)                     SKM_sk_num(rsync_ctx_t, (st))
#define sk_rsync_ctx_t_value(st, i)                SKM_sk_value(rsync_ctx_t, (st), (i))
#define sk_rsync_ctx_t_set(st, i, val)             SKM_sk_set(rsync_ctx_t, (st), (i), (val))
#define sk_rsync_ctx_t_zero(st)                    SKM_sk_zero(rsync_ctx_t, (st))
#define sk_rsync_ctx_t_push(st, val)               SKM_sk_push(rsync_ctx_t, (st), (val))
#define sk_rsync_ctx_t_unshift(st, val)            SKM_sk_unshift(rsync_ctx_t, (st), (val))
#define sk_rsync_ctx_t_find(st, val)               SKM_sk_find(rsync_ctx_t, (st), (val))
#define sk_rsync_ctx_t_find_ex(st, val)            SKM_sk_find_ex(rsync_ctx_t, (st), (val))
#define sk_rsync_ctx_t_delete(st, i)               SKM_sk_delete(rsync_ctx_t, (st), (i))
#define sk_rsync_ctx_t_delete_ptr(st, ptr)         SKM_sk_delete_ptr(rsync_ctx_t, (st), (ptr))
#define sk_rsync_ctx_t_insert(st, val, i)          SKM_sk_insert(rsync_ctx_t, (st), (val), (i))
#define sk_rsync_ctx_t_set_cmp_func(st, cmp)       SKM_sk_set_cmp_func(rsync_ctx_t, (st), (cmp))
#define sk_rsync_ctx_t_dup(st)                     SKM_sk_dup(rsync_ctx_t, st)
#define sk_rsync_ctx_t_pop_free(st, free_func)     SKM_sk_pop_free(rsync_ctx_t, (st), (free_func))
#define sk_rsync_ctx_t_shift(st)                   SKM_sk_shift(rsync_ctx_t, (st))
#define sk_rsync_ctx_t_pop(st)                     SKM_sk_pop(rsync_ctx_t, (st))
#define sk_rsync_ctx_t_sort(st)                    SKM_sk_sort(rsync_ctx_t, (st))
#define sk_rsync_ctx_t_is_sorted(st)               SKM_sk_is_sorted(rsync_ctx_t, (st))

/*
 * Safestack macros for rsync_history_t.
 */
#define sk_rsync_history_t_new(st)                     SKM_sk_new(rsync_history_t, (st))
#define sk_rsync_history_t_new_null()                  SKM_sk_new_null(rsync_history_t)
#define sk_rsync_history_t_free(st)                    SKM_sk_free(rsync_history_t, (st))
#define sk_rsync_history_t_num(st)                     SKM_sk_num(rsync_history_t, (st))
#define sk_rsync_history_t_value(st, i)                SKM_sk_value(rsync_history_t, (st), (i))
#define sk_rsync_history_t_set(st, i, val)             SKM_sk_set(rsync_history_t, (st), (i), (val))
#define sk_rsync_history_t_zero(st)                    SKM_sk_zero(rsync_history_t, (st))
#define sk_rsync_history_t_push(st, val)               SKM_sk_push(rsync_history_t, (st), (val))
#define sk_rsync_history_t_unshift(st, val)            SKM_sk_unshift(rsync_history_t, (st), (val))
#define sk_rsync_history_t_find(st, val)               SKM_sk_find(rsync_history_t, (st), (val))
#define sk_rsync_history_t_find_ex(st, val)            SKM_sk_find_ex(rsync_history_t, (st), (val))
#define sk_rsync_history_t_delete(st, i)               SKM_sk_delete(rsync_history_t, (st), (i))
#define sk_rsync_history_t_delete_ptr(st, ptr)         SKM_sk_delete_ptr(rsync_history_t, (st), (ptr))
#define sk_rsync_history_t_insert(st, val, i)          SKM_sk_insert(rsync_history_t, (st), (val), (i))
#define sk_rsync_history_t_set_cmp_func(st, cmp)       SKM_sk_set_cmp_func(rsync_history_t, (st), (cmp))
#define sk_rsync_history_t_dup(st)                     SKM_sk_dup(rsync_history_t, st)
#define sk_rsync_history_t_pop_free(st, free_func)     SKM_sk_pop_free(rsync_history_t, (st), (free_func))
#define sk_rsync_history_t_shift(st)                   SKM_sk_shift(rsync_history_t, (st))
#define sk_rsync_history_t_pop(st)                     SKM_sk_pop(rsync_history_t, (st))
#define sk_rsync_history_t_sort(st)                    SKM_sk_sort(rsync_history_t, (st))
#define sk_rsync_history_t_is_sorted(st)               SKM_sk_is_sorted(rsync_history_t, (st))

/*
 * Safestack macros for task_t.
 */
#define sk_task_t_new(st)                     SKM_sk_new(task_t, (st))
#define sk_task_t_new_null()                  SKM_sk_new_null(task_t)
#define sk_task_t_free(st)                    SKM_sk_free(task_t, (st))
#define sk_task_t_num(st)                     SKM_sk_num(task_t, (st))
#define sk_task_t_value(st, i)                SKM_sk_value(task_t, (st), (i))
#define sk_task_t_set(st, i, val)             SKM_sk_set(task_t, (st), (i), (val))
#define sk_task_t_zero(st)                    SKM_sk_zero(task_t, (st))
#define sk_task_t_push(st, val)               SKM_sk_push(task_t, (st), (val))
#define sk_task_t_unshift(st, val)            SKM_sk_unshift(task_t, (st), (val))
#define sk_task_t_find(st, val)               SKM_sk_find(task_t, (st), (val))
#define sk_task_t_find_ex(st, val)            SKM_sk_find_ex(task_t, (st), (val))
#define sk_task_t_delete(st, i)               SKM_sk_delete(task_t, (st), (i))
#define sk_task_t_delete_ptr(st, ptr)         SKM_sk_delete_ptr(task_t, (st), (ptr))
#define sk_task_t_insert(st, val, i)          SKM_sk_insert(task_t, (st), (val), (i))
#define sk_task_t_set_cmp_func(st, cmp)       SKM_sk_set_cmp_func(task_t, (st), (cmp))
#define sk_task_t_dup(st)                     SKM_sk_dup(task_t, st)
#define sk_task_t_pop_free(st, free_func)     SKM_sk_pop_free(task_t, (st), (free_func))
#define sk_task_t_shift(st)                   SKM_sk_shift(task_t, (st))
#define sk_task_t_pop(st)                     SKM_sk_pop(task_t, (st))
#define sk_task_t_sort(st)                    SKM_sk_sort(task_t, (st))
#define sk_task_t_is_sorted(st)               SKM_sk_is_sorted(task_t, (st))

#endif /* __RCYNIC_C__DEFSTACK_H__ */
