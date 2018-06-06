#ifndef __qos_history_h__
#define __qos_history_h__

#include <config.h>
#include <assert.h>
#include <sys/types.h>
#include <config.h>
#include <lib/bsd-list.h>
#include <scheduler.h>
#include <packet.h>

#define DOWN_LINK 0 // away from the GL
#define UP_LINK 1 // toward the GL
#define INFINITY4 0xffff
#define INFINITY8 0xffffffff

class qos_entry
{ 
public:
	qos_entry();
	~qos_entry();
	double getQoSVal();
	nsaddr_t getOtrId();
	void setQoSVal(double qos_val);
	void setOtrId(nsaddr_t otrId);
protected:	
	nsaddr_t otrId;
	double   qos_val;
};

class qos_record {
	friend class qos_entry;
	friend class qos_history;
public:
	qos_record(u_int32_t seq_no);
	~qos_record();
	qos_record*       next();
	qos_entry *getQoSEntry(u_int8_t direction);
	u_int32_t getSeqNo();
protected:
	u_int32_t seq_no;
	qos_entry* qos_val[2];
	qos_record *next_;
};

class qos_history {
	friend class qos_entry;
	friend class qos_record;
	
public: 
	qos_history();
	~qos_history();
	qos_record*       first() {return head_; }
	qos_record*       last() {return tail_; }
    qos_record*       lookup(u_int32_t seq_no);
    qos_record* 	  get_current_record_ptr();
    void set_current_record_ptr(qos_record* qr);
    bool              add(qos_record *qr);
    void 			  clear();
    bool 			  remove(qos_record* qr);
    u_int32_t	      size();
	void incr_num_samples_sent();
    void set_num_samples_sent(u_int32_t numSent);
	u_int32_t get_num_samples_sent();
	void set_max_qos_est(double qos_val);
	double get_max_qos_est();
	void set_min_qos_est(double qos_val);
	double get_min_qos_est();
	void set_max_qos_otrId(nsaddr_t otrId);
	nsaddr_t get_max_qos_otrId();
	void set_min_qos_otrId(nsaddr_t otrId);
	nsaddr_t get_min_qos_otrId();
	void reinitializeQoSEstimates();
	void incrementCountQoSPackets();
	void decrementCountQoSPackets();
	u_int8_t getCountQoSPackets();

protected:
    u_int8_t countQoSPackets;
	u_int32_t num_samples_sent;
	u_int32_t num_samples_recvd;
	double max_qos_est;
	double min_qos_est;
	nsaddr_t max_qos_otrId;
	nsaddr_t min_qos_otrId;
	qos_record*	head_;
	qos_record* current_record_ptr;
	qos_record*	tail_;
};

#endif
