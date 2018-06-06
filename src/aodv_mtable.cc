#include "aodv/aodv_mtable.h"

/* =====================================================================
   The Multicast Routing Table
   ===================================================================== */

aodv_mt_entry::aodv_mt_entry(nsaddr_t id)
{
	mt_dst = id;
	mt_flags = MTF_DOWN;
    mt_node_status = NOT_ON_TREE;
	mt_grp_leader_addr = INFINITY8;
	mt_seqno = 0;
	mt_hops_grp_leader = INFINITY8;
	
	mt_req_last_ttl = 0;
	mt_req_cnt = 0;
	mt_req_times = 0;

	mt_rep_grp_leader_addr = INFINITY8;
	mt_rep_seqno = 0;
	mt_rep_hops_tree = INFINITY4;
	mt_rep_hops_grp_leader = INFINITY4;
	mt_rep_selected_upstream = INFINITY8;
	mt_rep_timeout = 0;
    mt_rep_ipdst = INFINITY8;

    mt_keep_on_tree_timeout = 0;
    mt_prev_grp_leader_addr = INFINITY8;

    mt_grp_merge_permission = INFINITY8;
	mt_grp_merge_timeout = 0;
   
	// Initialize QoS History
    qh = new qos_history();
    gl_qh = new gl_qos_history();
};


/* =====================================================================
   The Multicast Routing Table
   ===================================================================== */
aodv_mt_entry* aodv_mtable::mt_lookup(nsaddr_t id)
{
	aodv_mt_entry *mt = mthead.lh_first;

	for(; mt; mt = mt->mt_link.le_next) {
		if(mt->mt_dst == id)
		break;
	}
	return mt;
}

void
aodv_mtable::mt_delete(nsaddr_t id)
{
	aodv_mt_entry *mt = mt_lookup(id);

	if(mt) {
		LIST_REMOVE(mt, mt_link);
		delete mt;
	}
}

aodv_mt_entry*
aodv_mtable::mt_add(nsaddr_t id)
{
	aodv_mt_entry *mt;

	mt = new aodv_mt_entry(id);
	assert(mt);

	LIST_INSERT_HEAD(&mthead, mt, mt_link);

	return mt;
}

void aodv_mtable::setLinkDelay(nsaddr_t src_id, nsaddr_t dst, u_int32_t seqno, double delay, u_int8_t direction) {
	aodv_mt_entry *mt = mt_lookup(dst);
	qos_record* qr;
	qos_history *qh;
	qos_entry *qe;
	if(mt) {
		qh = mt->qh;
		qr = qh->lookup(seqno);
	    
		if(!qr) {// create new qos_record for "seqno"
			qr = new qos_record(seqno);
			qh->add(qr);
		}
		// update available qos_record	
		qe = qr->getQoSEntry(direction);
		qe->setQoSVal(delay);
		qe->setOtrId(src_id);
	}		
}

void aodv_mtable::dumpQoSVals(nsaddr_t src_id, nsaddr_t dst, qos_element* qos_array, u_int8_t direction) {
	aodv_mt_entry *mt = mt_lookup(dst);
	qos_history* qh;
	qos_record* qr;
	qos_record* prev_qr; // Added by mk @ Aug 19, 2005
	qos_entry *qe;
	u_int32_t i = 0;
	u_int8_t opposite_direction = 0;
	
	if(direction == 1)
	  opposite_direction = 0;
	else
	  opposite_direction = 1;
	
	if(mt) {
		qh = mt->qh;

		if((qh->size() - qh->get_num_samples_sent()) == MAX_QoS_SAMPLES) { 
		  qr = qh->first(); 
		  if(qh->get_current_record_ptr() != NULL) 
		    qr = qh->get_current_record_ptr()->next(); //XXX: next ptr may be NULL 
		  else
   		    printf(" Node %d, current record ptr is NULL = %x \n", src_id, qh->get_current_record_ptr());
   
		   //printf(" Node %d, (qh-size - sent samples) = %d, qr->seqNo = %d\n", src_id, (qh->size() - qh->get_num_samples_sent()), qr->getSeqNo());    
 	    } /* if */
		
	    if((qh->size() - qh->get_num_samples_sent()) > MAX_QoS_SAMPLES) { 
		  //First Step: Move the CurrentRecordPtr from 0 to num_samples_sent
		  i = 0;  // reinitialize 'i' for use in the next loop ...
		  qr = qh->first();
		  prev_qr = qr; // Added by mk @ Aug 19, 2005
		  while((qr != NULL) && (i < (qh->size() - MAX_QoS_SAMPLES))) {
			prev_qr = qr; // Added by mk @ Aug 19, 2005
		    qr = qr->next();  
		    i++;
		  }
		  qr = prev_qr; // Added by mk @ Aug 19, 2005
		  qh->set_current_record_ptr(qr); //XXX: next ptr may be NULL
		  i = 0;  // reinitialize 'i' for use in the next loop ...
		  u_int32_t range = ((qh->size() - MAX_QoS_SAMPLES)- qh->get_num_samples_sent());
		  for(i = 0; i < range ; i++) {
			 qh->incr_num_samples_sent();
		  }		  
	    } /* if */
	    
	    i=0; // reinitialize 'i' for reuse in the next loop ...
	    
		while ((qr != NULL)&&(i < MAX_QoS_SAMPLES)) {
		   //if((qr->getQoSEntry(UP_LINK))&&(qr->getQoSEntry(DOWN_LINK))) {
			 if(qr->getQoSEntry(UP_LINK)->getQoSVal() != INFINITY8) {
				if(qr->getQoSEntry(DOWN_LINK)->getQoSVal() == INFINITY8) 
				  qr->getQoSEntry(DOWN_LINK)->setQoSVal(qr->getQoSEntry(UP_LINK)->getQoSVal());
			    qos_array[i].seq_no = qr->getSeqNo();
				qos_array[i].qos_val = qr->getQoSEntry(direction)->getQoSVal(); 
				//qos_array[i].qos_val = qr->getQoSEntry(UP_LINK)->getQoSVal(); // commented by mk @ Aug 19, 2005
				
				qh->incr_num_samples_sent();
				qh->set_current_record_ptr(qr);
				printf("**************** Node %d is sending the %d sample with seqNo = %d and numSamplesSent = %d currrecrdptr->seq = %d and currrecrdptr = %x \n", src_id, i, qr->getSeqNo(), qh->get_num_samples_sent(), qh->get_current_record_ptr()->getSeqNo(), qh->get_current_record_ptr());
				i++;
			} /* if */
		  qr = qr->next();
		} /* while */
	}	
}

void aodv_mtable::purgeQoSHistory(nsaddr_t mcast_grp_addr, nsaddr_t index, double purgeFraction) {
	aodv_mt_entry *mt = mt_lookup(mcast_grp_addr);
	qos_history* qh;
	qos_record* qr;
	qos_record* next;
	u_int32_t purge_samples;
	u_int32_t i = 0;
	if(mt) {
	  qh = mt->qh;
	  purge_samples = (u_int32_t)(purgeFraction*qh->size());
	  qr = qh->first();
	  while((qr != NULL) && (i < purge_samples)) {
		  next = qr->next();   
		  qh->remove(qr);
		  qr = next; 
		  i++;
	  }
	  
	  if(qh->size() <= MAX_QoS_SAMPLES)
	    qh->set_current_record_ptr(NULL);
	  
	  if(qh->get_num_samples_sent() < purge_samples)
	    qh->set_num_samples_sent(0);
	  else
	    qh->set_num_samples_sent(qh->get_num_samples_sent() - purge_samples);
    } /* if */
}

