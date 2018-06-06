#ifndef __gl_qos_history__
#define __gl_qos_history__

#include <config.h>
#include <assert.h>
#include <sys/types.h>
#include <config.h>
#include <lib/bsd-list.h>
#include <scheduler.h>
#include <packet.h>

#define INFINITY4 0xffff
#define INFINITY8 0xffffffff

class otr_qos_est_entry {
	friend class otr_qos_est_list;
	friend class gl_qos_history;

public:
	otr_qos_est_entry(double qos_est, double timestamp);
	~otr_qos_est_entry();
	
	double get_qos_est();
	double get_timestamp();
	void set_qos_est(double qos_est);
	void set_timestamp(double timestamp); 
	otr_qos_est_entry*         next();

protected:
	  double timestamp; // Packet timestamp acke'd by the tree leaf and then updated by forwarders to GL ...
	  double qos_estimate;
      otr_qos_est_entry *nextEntry_;
};

class otr_qos_est_list {
	friend class otr_qos_est_entry;
	friend class gl_qos_history;

public:
	otr_qos_est_list(nsaddr_t otrId);
	~otr_qos_est_list();
	
	otr_qos_est_entry*         oldest_qos_est() {return headEntry_; }
    otr_qos_est_entry*         latest_qos_est() { return tailEntry_;}
    otr_qos_est_list*          next_otr_qos_est_list() {return nextList_;}
    bool                       add_qos_est(otr_qos_est_entry *oe);
    void 			           clear();
    bool 			           remove_qos_est(otr_qos_est_entry* oe);
	otr_qos_est_entry*         get_max_qos_est_entry();
	double                     get_weighted_qos_est(double alpha);
	u_int8_t                   size();
	nsaddr_t                   get_otr_id() {return otr_id; }
	
protected:  	  
  	  nsaddr_t otr_id;
	  otr_qos_est_entry* headEntry_;
  	  otr_qos_est_entry* tailEntry_;
	  otr_qos_est_list* nextList_;
};

class gl_qos_history {
	friend class otr_qos_est_entry;
	friend class otr_qos_est_list;
	
public:		
	gl_qos_history();
	~gl_qos_history();
	
	otr_qos_est_list*         first_otr() {return headList_; }
	u_int8_t                  numOtrs() ;
	bool                      add_otr(otr_qos_est_list *ole);
	bool                      remove_otr(otr_qos_est_list *ole);
	otr_qos_est_list*         lookup_otr(nsaddr_t otr_id);
	bool                      add_otr_qos_est(nsaddr_t otr_id, double qos_est, double timestamp);
    otr_qos_est_list*         get_max_qos_est_list();
	otr_qos_est_list*         get_max_latest_qos_est_list();
	otr_qos_est_list*         get_max_weighted_qos_est_list(double alpha);
	void                      clear_gl_qh_history();

	protected:
	  otr_qos_est_list* headList_;
	  otr_qos_est_list* tailList_;
};

#endif
