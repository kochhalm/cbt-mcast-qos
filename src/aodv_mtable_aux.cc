#include <assert.h>
#include "aodv/aodv_mtable_aux.h"

/* ======================================================================
   Next Hop List used by AODV Mcast Table.
   ===================================================================== */

aodv_nh_entry::aodv_nh_entry(nsaddr_t hop)
{
	next_hop = hop;
	enabled_flag = NH_DISABLE;
	link_direction = NH_DOWNSTREAM;
    link_expire = 0;
	next_ = NULL;
}

aodv_nhlist::aodv_nhlist()
{
	head_ = tail_ = NULL;
}

aodv_nhlist::~aodv_nhlist()
{
    aodv_nh_entry *p;
    while(head_){
        p = head_;
        head_ = p->next_;
        delete p;
    }
    tail_ = NULL;
}

aodv_nh_entry* aodv_nhlist::lookup(nsaddr_t hop)
{
    aodv_nh_entry *p = head_;
    while(p){
        if (p->next_hop == hop) return p;
        p = p->next_;
    }

    return NULL;
}

aodv_nh_entry* aodv_nhlist::hop()
{
    aodv_nh_entry *p = head_;
    while(p){
        if (p->enabled_flag == NH_ENABLE) return p;
        p = p->next_;
    }

    return NULL;
}

aodv_nh_entry* aodv_nhlist::hopExcept(nsaddr_t hop)
{
	aodv_nh_entry *p = head_;
    while(p){
        if (p->next_hop != hop && p->enabled_flag == NH_ENABLE) return p;
        p = p->next_;
    }

    return NULL;
}

u_int8_t aodv_nhlist::size(){
	u_int8_t count = 0;
	aodv_nh_entry *p = head_;
    while(p){
		if (p->enabled_flag == NH_ENABLE) count++;
        p = p->next_;
	}

	return count;
}

aodv_nh_entry* aodv_nhlist::upstream(){
	aodv_nh_entry *p = head_;
    while(p){
        if (p->link_direction == NH_UPSTREAM && p->enabled_flag == NH_ENABLE) return p;
        p = p->next_;
    }

    return NULL;
}

aodv_nh_entry* aodv_nhlist::downstream(){
	aodv_nh_entry *p = head_;
    while(p){
        if (p->link_direction == NH_DOWNSTREAM && p->enabled_flag == NH_ENABLE) return p;
        p = p->next_;
    }

    return NULL;
}

void aodv_nhlist::clear(){
    aodv_nh_entry *p;
    while(head_){
        p = head_;
        head_ = p->next_;
        delete p;
    }
    tail_ = NULL;
}

bool aodv_nhlist::remove(aodv_nh_entry *nh){
    if (head_ == nh) {
        head_ = nh->next_;
        if (tail_ == nh){
            if (head_ != NULL){
                printf("error when remove nh\n");
                exit(1);
            }
            tail_=NULL;
        }
        
        delete nh;
        return true;
    }
    else {
        aodv_nh_entry *prev = head_, *p = head_->next_;

        while (p){
            if (p == nh){
                p = p->next_;
                prev->next_ = p;
                if (tail_ == nh){
                    tail_ = prev;
                    if (p != NULL){
                       printf("error when remove nh\n");
                       exit(1);
                    }
                }
                delete nh;
                
                return true;
            }
            prev = p;
            p = p->next_;
        }

        return false;
    }
      
}    

bool aodv_nhlist::add(aodv_nh_entry *nh){
    if (head_ == NULL){
        head_ = tail_ = nh;
        head_->next_ = NULL;
    }
    else {
        tail_->next_ = nh;
        tail_ = nh;
    }
    return true;
}
/* ======================================================================
   Group Leader Table used by AODV Mcast Table.
   ===================================================================== */
aodv_glt_entry*  aodv_gltable::glt_add(nsaddr_t id){
    aodv_glt_entry *glt;

    assert(glt_lookup(id) == NULL);
    glt = new aodv_glt_entry(id);
    assert(glt);

    LIST_INSERT_HEAD(&glthead, glt, glt_link);
    return glt;
}

aodv_glt_entry* aodv_gltable::glt_lookup(nsaddr_t id){
    aodv_glt_entry *glt = glthead.lh_first;

	for(; glt; glt = glt->glt_link.le_next) {
		if(glt->glt_grp_addr == id)
		break;
	}
	return glt;
}

