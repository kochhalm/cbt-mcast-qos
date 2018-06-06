void AODV::groupLeaderMigrationDecision(Packet *p) {
  struct hdr_ip *ih = HDR_IP(p);    
  struct hdr_aodv_qos *qos_hdr = HDR_AODV_QOS(p);
  nsaddr_t dst = ih->daddr();
  nsaddr_t src = ih->saddr(); //the immediate source of the QoSPacket is our neighboring Otr
  aodv_mt_entry *mt = mtable.mt_lookup(qos_hdr->qh_grp_dst);
  double delay_estimate = qos_hdr->qh_delay_estimate;
  double qos_pkt_timestamp = qos_hdr->qh_timestamp;
  gl_qos_history *gl_qh;
   	
  if(mt) {
    gl_qh = mt->gl_qh;
    gl_qh->add_otr_qos_est(src, delay_estimate, qos_pkt_timestamp);
    
    displayNodeInfo(qos_hdr->qh_grp_dst);
        
    if(gl_qh->numOtrs() >= 2) { 
	  //The GL needs atleast one QoSPacket (history) from all of the existing neighboring otrs to make a migration decision ...
      //XXX: What if the otr with maximum branch delay is no longer a neighbor ?
  	  otr_qos_est_list* max_qos_est_list = getExistingMaxDelayOtr(mt);

  	  if(max_qos_est_list) {
   	    //otr_qos_est_entry* max_qos_est_entry = max_qos_est_list->get_max_qos_est_entry(); //max_qos_est_list->latest_qos_est();
  	    double max_delay = max_qos_est_list->get_weighted_qos_est(alpha);//max_qos_est_entry->get_qos_est();
  	    nsaddr_t max_delay_otr = max_qos_est_list->get_otr_id();
	    if((max_delay - qos_target) >= qos_margin) {	
 	      if(index != max_delay_otr)  {//XXX: Hack for packets that return from the sender to itself. In this case from grp-leader to itself.  
            printf("\n\n[!****! %d@%.9f: GL: delay_estimate = %.9f: qos_imbalance = %.9f: otrId = %d]\n\n",index, CURRENT_TIME, max_delay, ((qos_target + qos_margin) - max_delay), max_delay_otr);       	    	    
            //displayGroupInformation(mt);
            migrateGroupLeader(mt, max_delay_otr);
          }
	    } /* if */  
      } /* if */
    } /* if */ 
  } /* if */
}