/*
 * Automatically generated, do not edit.
 * Generator $Id: defstack.py 4725 2012-09-19 21:28:34Z sra $
 */

#ifndef __RPKI_ROA_H__DEFSTACK_H__
#define __RPKI_ROA_H__DEFSTACK_H__

/*
 * Safestack macros for ROAIPAddress.
 */
#define sk_ROAIPAddress_new(st)                     SKM_sk_new(ROAIPAddress, (st))
#define sk_ROAIPAddress_new_null()                  SKM_sk_new_null(ROAIPAddress)
#define sk_ROAIPAddress_free(st)                    SKM_sk_free(ROAIPAddress, (st))
#define sk_ROAIPAddress_num(st)                     SKM_sk_num(ROAIPAddress, (st))
#define sk_ROAIPAddress_value(st, i)                SKM_sk_value(ROAIPAddress, (st), (i))
#define sk_ROAIPAddress_set(st, i, val)             SKM_sk_set(ROAIPAddress, (st), (i), (val))
#define sk_ROAIPAddress_zero(st)                    SKM_sk_zero(ROAIPAddress, (st))
#define sk_ROAIPAddress_push(st, val)               SKM_sk_push(ROAIPAddress, (st), (val))
#define sk_ROAIPAddress_unshift(st, val)            SKM_sk_unshift(ROAIPAddress, (st), (val))
#define sk_ROAIPAddress_find(st, val)               SKM_sk_find(ROAIPAddress, (st), (val))
#define sk_ROAIPAddress_find_ex(st, val)            SKM_sk_find_ex(ROAIPAddress, (st), (val))
#define sk_ROAIPAddress_delete(st, i)               SKM_sk_delete(ROAIPAddress, (st), (i))
#define sk_ROAIPAddress_delete_ptr(st, ptr)         SKM_sk_delete_ptr(ROAIPAddress, (st), (ptr))
#define sk_ROAIPAddress_insert(st, val, i)          SKM_sk_insert(ROAIPAddress, (st), (val), (i))
#define sk_ROAIPAddress_set_cmp_func(st, cmp)       SKM_sk_set_cmp_func(ROAIPAddress, (st), (cmp))
#define sk_ROAIPAddress_dup(st)                     SKM_sk_dup(ROAIPAddress, st)
#define sk_ROAIPAddress_pop_free(st, free_func)     SKM_sk_pop_free(ROAIPAddress, (st), (free_func))
#define sk_ROAIPAddress_shift(st)                   SKM_sk_shift(ROAIPAddress, (st))
#define sk_ROAIPAddress_pop(st)                     SKM_sk_pop(ROAIPAddress, (st))
#define sk_ROAIPAddress_sort(st)                    SKM_sk_sort(ROAIPAddress, (st))
#define sk_ROAIPAddress_is_sorted(st)               SKM_sk_is_sorted(ROAIPAddress, (st))

/*
 * Safestack macros for ROAIPAddressFamily.
 */
#define sk_ROAIPAddressFamily_new(st)                     SKM_sk_new(ROAIPAddressFamily, (st))
#define sk_ROAIPAddressFamily_new_null()                  SKM_sk_new_null(ROAIPAddressFamily)
#define sk_ROAIPAddressFamily_free(st)                    SKM_sk_free(ROAIPAddressFamily, (st))
#define sk_ROAIPAddressFamily_num(st)                     SKM_sk_num(ROAIPAddressFamily, (st))
#define sk_ROAIPAddressFamily_value(st, i)                SKM_sk_value(ROAIPAddressFamily, (st), (i))
#define sk_ROAIPAddressFamily_set(st, i, val)             SKM_sk_set(ROAIPAddressFamily, (st), (i), (val))
#define sk_ROAIPAddressFamily_zero(st)                    SKM_sk_zero(ROAIPAddressFamily, (st))
#define sk_ROAIPAddressFamily_push(st, val)               SKM_sk_push(ROAIPAddressFamily, (st), (val))
#define sk_ROAIPAddressFamily_unshift(st, val)            SKM_sk_unshift(ROAIPAddressFamily, (st), (val))
#define sk_ROAIPAddressFamily_find(st, val)               SKM_sk_find(ROAIPAddressFamily, (st), (val))
#define sk_ROAIPAddressFamily_find_ex(st, val)            SKM_sk_find_ex(ROAIPAddressFamily, (st), (val))
#define sk_ROAIPAddressFamily_delete(st, i)               SKM_sk_delete(ROAIPAddressFamily, (st), (i))
#define sk_ROAIPAddressFamily_delete_ptr(st, ptr)         SKM_sk_delete_ptr(ROAIPAddressFamily, (st), (ptr))
#define sk_ROAIPAddressFamily_insert(st, val, i)          SKM_sk_insert(ROAIPAddressFamily, (st), (val), (i))
#define sk_ROAIPAddressFamily_set_cmp_func(st, cmp)       SKM_sk_set_cmp_func(ROAIPAddressFamily, (st), (cmp))
#define sk_ROAIPAddressFamily_dup(st)                     SKM_sk_dup(ROAIPAddressFamily, st)
#define sk_ROAIPAddressFamily_pop_free(st, free_func)     SKM_sk_pop_free(ROAIPAddressFamily, (st), (free_func))
#define sk_ROAIPAddressFamily_shift(st)                   SKM_sk_shift(ROAIPAddressFamily, (st))
#define sk_ROAIPAddressFamily_pop(st)                     SKM_sk_pop(ROAIPAddressFamily, (st))
#define sk_ROAIPAddressFamily_sort(st)                    SKM_sk_sort(ROAIPAddressFamily, (st))
#define sk_ROAIPAddressFamily_is_sorted(st)               SKM_sk_is_sorted(ROAIPAddressFamily, (st))

#endif /* __RPKI_ROA_H__DEFSTACK_H__ */
