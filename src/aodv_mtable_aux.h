#ifndef __nhlist_h__
#define __nhlist_h_

#include <config.h>
#include <assert.h>
#include <sys/types.h>
#include <config.h>
#include <lib/bsd-list.h>
#include <scheduler.h>
#include <packet.h>

#define NH_DISABLE	0
#define NH_ENABLE	1

#define NH_UPSTREAM 	0
#define NH_DOWNSTREAM	1

class aodv_nh_entry
{ 
	friend class AODV;
	friend class aodv_mt_entry;
	friend class aodv_nhlist;
public: 
	aodv_nh_entry(nsaddr_t hop);
	~aodv_nh_entry(){}

protected:
	nsaddr_t	next_hop;
	u_int8_t	enabled_flag;
	u_int8_t	link_direction;
	double      link_expire;
	aodv_nh_entry	*next_;
};

class aodv_nhlist {
public:
	aodv_nhlist();
	~aodv_nhlist();

	aodv_nh_entry*	lookup(nsaddr_t hop);
	aodv_nh_entry*	hop();
	aodv_nh_entry*	hopExcept(nsaddr_t hop);
	u_int8_t	size();
	aodv_nh_entry*   upstream();
    bool   add(aodv_nh_entry *nh);
	bool   remove(aodv_nh_entry *nh);
    aodv_nh_entry*   downstream();
	void   clear();
	aodv_nh_entry* first(){ return head_;}
	
private:
	aodv_nh_entry*	head_;
	aodv_nh_entry*	tail_;
};

#define INFINITY8 0xffffffff
/* Group Leader Table Entry*/

class aodv_glt_entry {
	friend class AODV;
	friend class aodv_gltable;

public:
        aodv_glt_entry(nsaddr_t id){
			glt_grp_addr = id;
			glt_expire = 0;
			glt_grp_leader_addr = INFINITY8;
			glt_next_hop = INFINITY8;
		}
		
        ~aodv_glt_entry(){}

protected:
        LIST_ENTRY(aodv_glt_entry) glt_link;

        double          glt_expire; 
		nsaddr_t		glt_grp_leader_addr;
		nsaddr_t		glt_grp_addr;
		nsaddr_t		glt_next_hop;
};


/* The Group Leader Table */

class aodv_gltable {
 public:
		aodv_gltable() { LIST_INIT(&glthead); }

        aodv_glt_entry*       head() { return glthead.lh_first; }
        aodv_glt_entry*       glt_add(nsaddr_t id);
        aodv_glt_entry*       glt_lookup(nsaddr_t id);

 private:
        LIST_HEAD(, aodv_glt_entry) glthead;
};

#endif

