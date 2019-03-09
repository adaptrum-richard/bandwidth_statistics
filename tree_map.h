#ifndef __TREE_MAP_H__
#define __TREE_MAP_H__
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#ifndef __KERNEL__
#define __KERNEL__
#endif

#if __KERNEL__
	#define malloc(foo)	kmalloc(foo,GFP_ATOMIC)
	#define free(foo)	kfree(foo)
	#define printf(format,args...)	printk(format,##args)

	/* kernel strdup */
	static inline char *kernel_strdup(const char *str);
	static inline char *kernel_strdup(const char *str)
	{
		char *tmp;
		long int s;
		s=strlen(str) + 1;
		tmp = vmalloc(s);
		if (tmp != NULL)
		{
			memcpy(tmp, str, s);
		}
		return tmp;
	}
	#define strdup kernel_strdup

#endif



/* tree_map structs / prototypes */
typedef struct long_tree_map_node
{
	unsigned long key;
	void* value;
	
	signed char balance; 
	struct long_tree_map_node* left;
	struct long_tree_map_node* right;
} long_map_node;

typedef struct 
{
	long_map_node* root;
	unsigned long num_elements;

}long_map;

typedef struct
{
	long_map lm;
	unsigned char store_keys;
	unsigned long num_elements;

}string_map;



/* long map functions */
long_map* initialize_long_map(void);
void* get_long_map_element(long_map* map, unsigned long key);
void* get_smallest_long_map_element(long_map* map, unsigned long* smallest_key);
void* get_largest_long_map_element(long_map* map, unsigned long* largest_key);
void* remove_smallest_long_map_element(long_map* map, unsigned long* smallest_key);
void* remove_largest_long_map_element(long_map* map, unsigned long* largest_key);
void* set_long_map_element(long_map* map, unsigned long key, void* value);
void* remove_long_map_element(long_map* map, unsigned long key);
unsigned long* get_sorted_long_map_keys(long_map* map, unsigned long* num_keys_returned);
void** get_sorted_long_map_values(long_map* map, unsigned long* num_values_returned);
void** destroy_long_map(long_map* map, int destruction_type, unsigned long* num_destroyed);
void apply_to_every_long_map_value(long_map* map, void (*apply_func)(unsigned long key, void* value));

/* string map functions */
string_map* initialize_string_map(unsigned char store_keys);
void* get_string_map_element(string_map* map, const char* key);
void* get_string_map_element_with_hashed_key(string_map* map, unsigned long hashed_key);
void* set_string_map_element(string_map* map, const char* key, void* value);
void* remove_string_map_element(string_map* map, const char* key);
char** get_string_map_keys(string_map* map, unsigned long* num_keys_returned); 
void** get_string_map_values(string_map* map, unsigned long* num_values_returned);
void** destroy_string_map(string_map* map, int destruction_type, unsigned long* num_destroyed);
void apply_to_every_string_map_value(string_map* map, void (*apply_func)(char* key, void* value));


/*
 * three different ways to deal with values when data structure is destroyed
 */
#define DESTROY_MODE_RETURN_VALUES	20
#define DESTROY_MODE_FREE_VALUES 	21
#define DESTROY_MODE_IGNORE_VALUES	22


/* 
 * for convenience & backwards compatibility alias _string_map_ functions to 
 *  _map_ functions since string map is used more often than long map
 */
#define initialize_map		initialize_string_map
#define set_map_element		set_string_map_element
#define get_map_element		get_string_map_element
#define remove_map_element	remove_string_map_element
#define get_map_keys		get_string_map_keys
#define get_map_values		get_string_map_values
#define destroy_map		destroy_string_map


/* internal utility structures/ functions */
typedef struct stack_node_struct
{
	long_map_node** node_ptr;
	signed char direction;
	struct stack_node_struct* previous;
} stack_node;


/* internal for string map */
typedef struct 
{
	char* key;
	void* value;
} string_map_key_value;





/***************************************************
 * For testing only
 ***************************************************/
/*
void print_list(stack_node *l);

void print_list(stack_node *l)
{
	if(l != NULL)
	{
		printf(" list key = %ld, dir=%d, \n", (*(l->node_ptr))->key, l->direction);
		print_list(l->previous);
	}
}
*/
/******************************************************
 * End testing Code
 *******************************************************/



#endif