/*
 * Automatically generated, do not edit.
 * Generator $Id: defstack.awk 3985 2011-09-15 00:04:23Z sra $
 */

#ifndef __RPKI_MANIFEST_H__DEFSTACK_H__
#define __RPKI_MANIFEST_H__DEFSTACK_H__

/*
 * Safestack macros for FileAndHash.
 */
#define sk_FileAndHash_new(st)                     SKM_sk_new(FileAndHash, (st))
#define sk_FileAndHash_new_null()                  SKM_sk_new_null(FileAndHash)
#define sk_FileAndHash_free(st)                    SKM_sk_free(FileAndHash, (st))
#define sk_FileAndHash_num(st)                     SKM_sk_num(FileAndHash, (st))
#define sk_FileAndHash_value(st, i)                SKM_sk_value(FileAndHash, (st), (i))
#define sk_FileAndHash_set(st, i, val)             SKM_sk_set(FileAndHash, (st), (i), (val))
#define sk_FileAndHash_zero(st)                    SKM_sk_zero(FileAndHash, (st))
#define sk_FileAndHash_push(st, val)               SKM_sk_push(FileAndHash, (st), (val))
#define sk_FileAndHash_unshift(st, val)            SKM_sk_unshift(FileAndHash, (st), (val))
#define sk_FileAndHash_find(st, val)               SKM_sk_find(FileAndHash, (st), (val))
#define sk_FileAndHash_find_ex(st, val)            SKM_sk_find_ex(FileAndHash, (st), (val))
#define sk_FileAndHash_delete(st, i)               SKM_sk_delete(FileAndHash, (st), (i))
#define sk_FileAndHash_delete_ptr(st, ptr)         SKM_sk_delete_ptr(FileAndHash, (st), (ptr))
#define sk_FileAndHash_insert(st, val, i)          SKM_sk_insert(FileAndHash, (st), (val), (i))
#define sk_FileAndHash_set_cmp_func(st, cmp)       SKM_sk_set_cmp_func(FileAndHash, (st), (cmp))
#define sk_FileAndHash_dup(st)                     SKM_sk_dup(FileAndHash, st)
#define sk_FileAndHash_pop_free(st, free_func)     SKM_sk_pop_free(FileAndHash, (st), (free_func))
#define sk_FileAndHash_shift(st)                   SKM_sk_shift(FileAndHash, (st))
#define sk_FileAndHash_pop(st)                     SKM_sk_pop(FileAndHash, (st))
#define sk_FileAndHash_sort(st)                    SKM_sk_sort(FileAndHash, (st))
#define sk_FileAndHash_is_sorted(st)               SKM_sk_is_sorted(FileAndHash, (st))

#endif /* __RPKI_MANIFEST_H__DEFSTACK_H__ */
