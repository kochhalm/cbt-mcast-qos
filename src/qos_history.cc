#include <assert.h>
#include "aodv/qos_history.h"

/* =====================================================================
							   QoS Entry
   ===================================================================== */

qos_entry::qos_entry() {
	otrId = INFINITY4;
	qos_val = INFINITY8;
}

qos_entry::~qos_entry() {
	
}
   
double qos_entry::getQoSVal() {
	return qos_val;	
}

nsaddr_t qos_entry::getOtrId() {
	return otrId;	
}   

void qos_entry::setQoSVal(double val) {
	qos_val = val;	
}

void qos_entry::setOtrId(nsaddr_t id) {
	otrId =id;	
}

/* =====================================================================
							   QoS Record
   ===================================================================== */
   
qos_record::qos_record(u_int32_t seqNo) {   
   seq_no = seqNo;
   qos_val[0] = new qos_entry();
   qos_val[1] = new qos_entry();
   next_ = NULL;
}

qos_record::~qos_record()
{
	delete qos_val[0];
	delete qos_val[1];
}   


qos_record* qos_record::next() {
	return next_;
}

qos_entry* qos_record::getQoSEntry(u_int8_t direction) {
	if(direction == 0)
	  return qos_val[0];	
	return qos_val[1];	
}

u_int32_t qos_record::getSeqNo() {
	return seq_no;
}

/* =====================================================================
							   QoS History
   ===================================================================== */

qos_history::qos_history()
{
	head_ = tail_ = NULL;
	num_samples_sent = 0;
	current_record_ptr = NULL;
	num_samples_recvd = 0;
	max_qos_est = 0.0;
	min_qos_est = INFINITY8; //gets initialized with the first qos_estimate update ...
	countQoSPackets = 0;
}

qos_history::~qos_history()
{
    qos_record *p;
    while(head_){
        p = head_;
        head_ = p->next_;
        delete p;
    }
    tail_ = NULL;
}

qos_record* qos_history::lookup(u_int32_t seq_no)
{
    qos_record *p = head_;
    while(p){
        if (p->seq_no == seq_no) return p;
        p = p->next_;
    }
    return NULL;
}

qos_record* qos_history::get_current_record_ptr() {
	return current_record_ptr;	
}

void qos_history::set_current_record_ptr(qos_record* qr) {
	current_record_ptr = qr;	
}

bool qos_history::add(qos_record *qr){
    if (head_ == NULL){
        head_ = tail_ = qr;
        head_->next_ = NULL;
    }
    else {
        tail_->next_ = qr;
        tail_ = qr;
    }
    return true;
}

void qos_history::clear(){
    qos_record *p;
    while(head_){
        p = head_;
        head_ = p->next_;
        delete p;
    }
    tail_ = NULL;
}

bool qos_history::remove(qos_record *qr){
    if (head_ == qr) {
        head_ = qr->next_;
        if (tail_ == qr){
            if (head_ != NULL){
                printf("error when remove qr\n");
                exit(1);
            }
            tail_=NULL;
        }
        
        delete qr;
        return true;
    }
    else {
        qos_record *prev = head_, *p = head_->next_;

        while (p){
            if (p == qr){
                p = p->next_;
                prev->next_ = p;
                if (tail_ == qr){
                    tail_ = prev;
                    if (p != NULL){
                       printf("error when remove qr\n");
                       exit(1);
                    }
                }
                delete qr;
                
                return true;
            }
            prev = p;
            p = p->next_;
        }

        return false;
    }
      
}    

u_int32_t qos_history::size(){
	u_int32_t count = 0;
	qos_record *p = head_;
    while(p){
		count++;
        p = p->next_;
	}
	return count;
}

void qos_history::incr_num_samples_sent() {
	num_samples_sent+=1;	
}

void qos_history::set_num_samples_sent(u_int32_t numSent) {
	num_samples_sent = numSent;
}

u_int32_t qos_history::get_num_samples_sent() {
	return 	num_samples_sent;
}

void qos_history::set_max_qos_est(double qos_val) {
	max_qos_est	 = qos_val;	
}

double qos_history::get_max_qos_est() {
	return max_qos_est;		
}

void qos_history::set_min_qos_est(double qos_val) {
	min_qos_est	 = qos_val;	
}

double qos_history::qos_history::get_min_qos_est() {
	return min_qos_est;		
}

void qos_history::set_max_qos_otrId(nsaddr_t otrId) {
	max_qos_otrId = otrId;	
}

nsaddr_t qos_history::get_max_qos_otrId() {
	return 	max_qos_otrId;
}

void qos_history::set_min_qos_otrId(nsaddr_t otrId) {
	min_qos_otrId = otrId;	
}

nsaddr_t qos_history::get_min_qos_otrId() {
	return 	min_qos_otrId;
}

void qos_history::reinitializeQoSEstimates() {
	max_qos_est = 0.0;
	max_qos_otrId = INFINITY4;
	min_qos_otrId = INFINITY4;
	min_qos_est = INFINITY8; 
	countQoSPackets = 0;
}

void qos_history::incrementCountQoSPackets() {
	countQoSPackets++;
}

void qos_history::decrementCountQoSPackets() {
	countQoSPackets--;
}

u_int8_t qos_history::getCountQoSPackets() {
   return countQoSPackets;	
} 

