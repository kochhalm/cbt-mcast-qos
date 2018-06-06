#include <assert.h>
#include "aodv/gl_qos_history.h"

/* =====================================================================
			    OTR QoS Estimate Entry (otr_qos_est_entry)
   ===================================================================== */

otr_qos_est_entry::otr_qos_est_entry(double qos_est, double timestamp) {
  timestamp = timestamp;
  qos_estimate = qos_est;
  nextEntry_ = NULL;
}

otr_qos_est_entry::~otr_qos_est_entry() {
	
}

double otr_qos_est_entry::get_qos_est() {
  return qos_estimate;
}

double otr_qos_est_entry::get_timestamp() {
  return timestamp;
}

void otr_qos_est_entry::set_qos_est(double qos_est) {
  qos_estimate = qos_est;
}

void otr_qos_est_entry::set_timestamp(double time_stamp) {
	timestamp = time_stamp;
}

otr_qos_est_entry*  otr_qos_est_entry::next() {
  return nextEntry_;	
}

/* =====================================================================
		List of estimated QoS entries for an OTR (otr_qos_est_list)
   ===================================================================== */
   
otr_qos_est_list::otr_qos_est_list(nsaddr_t otrId) {   
   headEntry_ = tailEntry_ = NULL;
   nextList_ = NULL;
   otr_id = otrId;
}

otr_qos_est_list::~otr_qos_est_list() {
	otr_qos_est_entry *p;
    while(headEntry_){
        p = headEntry_;
        headEntry_ = p->nextEntry_;
        delete p;
    }
    tailEntry_ = NULL;
}

bool otr_qos_est_list::add_qos_est(otr_qos_est_entry *oe) {
	if (headEntry_ == NULL){
        headEntry_ = tailEntry_ = oe;
        headEntry_->nextEntry_ = NULL;
    }
    else {
        tailEntry_->nextEntry_ = oe;
        tailEntry_ = oe;
    }
    return true;
}

void otr_qos_est_list::clear() {
	otr_qos_est_entry *p;
    while(headEntry_){
        p = headEntry_;
        headEntry_ = p->nextEntry_;
        delete p;
    }
    tailEntry_ = NULL;
}

bool otr_qos_est_list::remove_qos_est(otr_qos_est_entry* oe) {
    if (headEntry_ == oe) {
        headEntry_ = oe->nextEntry_;
        if (tailEntry_ == oe){
            if (headEntry_ != NULL){
                printf("error when remove oe\n");
                exit(1);
            }
            tailEntry_=NULL;
        }
        
        delete oe;
        return true;
    }
    else {
        otr_qos_est_entry *prev = headEntry_, *p = headEntry_->nextEntry_;

        while (p){
            if (p == oe){
                p = p->nextEntry_;
                prev->nextEntry_ = p;
                if (tailEntry_ == oe){
                    tailEntry_ = prev;
                    if (p != NULL){
                       printf("error when remove oe\n");
                       exit(1);
                    }
                }
                delete oe;
                
                return true;
            }
            prev = p;
            p = p->nextEntry_;
        }
        return false;
    }
}

otr_qos_est_entry* otr_qos_est_list::get_max_qos_est_entry() {
	otr_qos_est_entry* max_qos_est_entry;
	double max_qos_val = 0.0;
    otr_qos_est_entry *p = headEntry_;
    while(p){
	   if(max_qos_val <= p->get_qos_est()) { // <= means that we will get latest max value ...
	     max_qos_val = p->get_qos_est();
	     max_qos_est_entry = p;     
       }
        p = p->nextEntry_;
	}
	return max_qos_est_entry;	
}

double otr_qos_est_list::get_weighted_qos_est(double alpha) {
	double weighted_qos_val = 0.0;
    otr_qos_est_entry *p = headEntry_;
    
   if(size() == 1)
     return p->get_qos_est(); // There is no need to weigh one entry ...
      
    while(p){
	    weighted_qos_val = alpha*p->get_qos_est() + (1.0 - alpha)*weighted_qos_val;
        p = p->nextEntry_;
	}
	return weighted_qos_val;	
}

u_int8_t otr_qos_est_list::size() {
    u_int8_t count = 0;
	otr_qos_est_entry *p = headEntry_;
    while(p){
		count++;
        p = p->nextEntry_;
	}
	return count;
}
	
/* =====================================================================
				      GL QoS History (gl_qos_history)
   ===================================================================== */

gl_qos_history::gl_qos_history()
{
	headList_ = tailList_ = NULL;
}

gl_qos_history::~gl_qos_history()
{
    otr_qos_est_list *p;
    while(headList_){
        p = headList_;
        headList_ = p->nextList_;
        delete p;
    }
    tailList_ = NULL;
}
	
u_int8_t gl_qos_history::numOtrs() {
	u_int8_t count = 0;
	otr_qos_est_list *p = headList_;
    while(p){
		count++;
        p = p->nextList_;
	}

	return count;
}

bool gl_qos_history::add_otr(otr_qos_est_list *ole) {
	if (headList_ == NULL){
        headList_ = tailList_ = ole;
        headList_->nextList_ = NULL;
    }
    else {
        tailList_->nextList_ = ole;
        tailList_ = ole;
    }
    return true;
}

otr_qos_est_list* gl_qos_history::lookup_otr(nsaddr_t otr_id) {
  otr_qos_est_list *p = headList_;
  while(p){
   if (p->get_otr_id() == otr_id) return p;
      p = p->nextList_;
   }
   return NULL;	
}

bool gl_qos_history::remove_otr(otr_qos_est_list *ole) {
	if (headList_ == ole) {
        headList_ = ole->nextList_;
        if (tailList_ == ole){
            if (headList_ != NULL){
                printf("error when remove qr\n");
                exit(1);
            }
            tailList_=NULL;
        }
        
        delete ole;
        return true;
    }
    else {
        otr_qos_est_list *prev = headList_, *p = headList_->nextList_;
        while (p){
            if (p == ole){
                p = p->nextList_;
                prev->nextList_ = p;
                if (tailList_ == ole){
                    tailList_ = prev;
                    if (p != NULL){
                       printf("error when remove qr\n");
                       exit(1);
                    }
                }
                delete ole;
                return true;
            }
            prev = p;
            p = p->nextList_;
        }

        return false;
    }
}

bool gl_qos_history::add_otr_qos_est(nsaddr_t otr_id, double qos_est, double timestamp) {
    otr_qos_est_list* otr_list = lookup_otr(otr_id);
    otr_qos_est_entry* otr_qos_entry;
	if(!otr_list) {
	  //OTR doesnt exist ...   
	  otr_list = new otr_qos_est_list(otr_id);
	  //add new list ...
	  add_otr(otr_list);
    }
    otr_qos_entry = new otr_qos_est_entry(qos_est, timestamp);
	otr_list->add_qos_est(otr_qos_entry);
}

otr_qos_est_list* gl_qos_history::get_max_qos_est_list() {
	otr_qos_est_list* max_qos_est_list;
	double max_qos_val = 0.0;
    otr_qos_est_list *p = headList_;
    while(p){
	   if(max_qos_val <= p->get_max_qos_est_entry()->get_qos_est()) { // <= means that we will get latest max value ...
	     max_qos_val = p->get_max_qos_est_entry()->get_qos_est();
	     max_qos_est_list = p;     
       }
       p = p->nextList_;
	}
	return max_qos_est_list;	
}

otr_qos_est_list* gl_qos_history::get_max_latest_qos_est_list() {
	otr_qos_est_list* max_latest_qos_est_list;
	double max_qos_val = 0.0;
    otr_qos_est_list *p = headList_;
    while(p){
	   if(max_qos_val <= p->latest_qos_est()->get_qos_est()) { // <= means that we will get latest max value ...
	     max_qos_val = p->latest_qos_est()->get_qos_est();
	     max_latest_qos_est_list = p;     
       }
       p = p->nextList_;
	}
	return max_latest_qos_est_list;	
}

otr_qos_est_list* gl_qos_history::get_max_weighted_qos_est_list(double alpha) {
	otr_qos_est_list* max_weighted_qos_est_list;
	double max_qos_val = 0.0;
    otr_qos_est_list *p = headList_;
    while(p){
	   double weighted_qos_est = p->get_weighted_qos_est(alpha);
	   if(max_qos_val < weighted_qos_est) { 
	     max_qos_val = weighted_qos_est;
	     max_weighted_qos_est_list = p;     
       }
       p = p->nextList_;
	}
	return max_weighted_qos_est_list;	
}

void gl_qos_history::clear_gl_qh_history() {
	otr_qos_est_list *p;
    while(headList_) {
        p = headList_;
        headList_ = p->nextList_;
        delete p;
    }
    tailList_ = NULL;
}


