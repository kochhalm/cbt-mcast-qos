/*
Copyright (c) 1997, 1998 Carnegie Mellon University.  All Rights
Reserved. 

Permission to use, copy, modify, and distribute this
software and its documentation is hereby granted (including for
commercial or for-profit use), provided that both the copyright notice and this permission notice appear in all copies of the software, derivative works, or modified versions, and any portions thereof, and that both notices appear in supporting documentation, and that credit is given to Carnegie Mellon University in all publications reporting on direct or indirect use of this code or its derivatives.

ALL CODE, SOFTWARE, PROTOCOLS, AND ARCHITECTURES DEVELOPED BY THE CMU
MONARCH PROJECT ARE EXPERIMENTAL AND ARE KNOWN TO HAVE BUGS, SOME OF
WHICH MAY HAVE SERIOUS CONSEQUENCES. CARNEGIE MELLON PROVIDES THIS
SOFTWARE OR OTHER INTELLECTUAL PROPERTY IN ITS ``AS IS'' CONDITION,
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE OR
INTELLECTUAL PROPERTY, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.

Carnegie Mellon encourages (but does not require) users of this
software or intellectual property to return any improvements or
extensions that they make, and to grant Carnegie Mellon the rights to redistribute these changes without encumbrance.

The AODV code developed by the CMU/MONARCH group was optimized and tuned by Samir Das and Mahesh Marina, University of Cincinnati. The work was partially done in Sun Microsystems. Modified for gratuitous replies by Anant Utgikar, 09/16/02.

*/

//#include <ip.h>

#include <aodv/aodv.h>
#include <aodv/aodv_packet.h>
#include <random.h>
#include <cmu-trace.h>
//#include <energy-model.h>

#define max(a,b)        ( (a) > (b) ? (a) : (b) )
#define CURRENT_TIME    Scheduler::instance().clock()

//#define DEBUG
//#define ERROR

#ifdef DEBUG
static int extra_route_reply = 0;
static int limit_route_request = 0;
static int route_request = 0;
#endif


/*
  TCL Hooks
*/


int hdr_aodv::offset_;
static class AODVHeaderClass : public PacketHeaderClass {
public:
        AODVHeaderClass() : PacketHeaderClass("PacketHeader/AODV",
                                              sizeof(hdr_all_aodv)) {
	  bind_offset(&hdr_aodv::offset_);
	} 
} class_rtProtoAODV_hdr;

static class AODVclass : public TclClass {
public:
        AODVclass() : TclClass("Agent/AODV") {}
        TclObject* create(int argc, const char*const* argv) {
          assert(argc == 5);
          //return (new AODV((nsaddr_t) atoi(argv[4])));
	  return (new AODV((nsaddr_t) Address::instance().str2addr(argv[4])));
        }
} class_rtProtoAODV;


int
AODV::command(int argc, const char*const* argv) {
  if(argc == 2) {
  Tcl& tcl = Tcl::instance();
    
    if(strncasecmp(argv[1], "id", 2) == 0) {
      tcl.resultf("%d", index);
      return TCL_OK;
    }
    
    if(strncasecmp(argv[1], "start", 2) == 0) {
      btimer.handle((Event*) 0);

#ifdef MULTICAST
      ntimer.handle((Event*) 0);
      grphtimer.handle((Event*) 0);
#else
#ifndef AODV_LINK_LAYER_DETECTION
      htimer.handle((Event*) 0);
      ntimer.handle((Event*) 0); 
#endif // LINK LAYER DETECTION
#endif

      rtimer.handle((Event*) 0);
      return TCL_OK;
     }               
  }
  else if(argc == 3) {
    if(strcmp(argv[1], "index") == 0) {
      index = atoi(argv[2]);
      return TCL_OK;
    }

    else if(strcmp(argv[1], "log-target") == 0 || strcmp(argv[1], "tracetarget") == 0) {
      logtarget = (Trace*) TclObject::lookup(argv[2]);
      if(logtarget == 0)
	return TCL_ERROR;
      return TCL_OK;
    }
    else if(strcmp(argv[1], "drop-target") == 0) {
    int stat = rqueue.command(argc,argv);
      if (stat != TCL_OK) return stat;
      return Agent::command(argc, argv);
    }
    else if(strcmp(argv[1], "if-queue") == 0) {
    ifqueue = (PriQueue*) TclObject::lookup(argv[2]);
      
      if(ifqueue == 0) 
        return TCL_ERROR;
      return TCL_OK;
    }

#ifdef MULTICAST
    else if (strcmp(argv[1], "aodv-join-group") == 0){
        nsaddr_t mcast_addr = atoi(argv[2]);
        if (mcast_addr < IP_MULTICAST) return TCL_ERROR;
        aodv_mt_entry *mt = mtable.mt_lookup(mcast_addr);
        if (mt == 0) mt = mtable.mt_add(mcast_addr);
        if (mt->mt_node_status == ON_GROUP){
            return TCL_OK;
        }
        if (mt->mt_node_status == ON_TREE){
            mt->mt_node_status = ON_GROUP;
            return TCL_OK;
        }

        // node is not on the tree
        mt->mt_flags = MTF_IN_REPAIR;
        mt->mt_grp_leader_addr = INFINITY8;
        mt->mt_node_status = ON_GROUP;
 
        sendMRQ(mt, RREQ_J);
        return TCL_OK;
    }
    else if (strcmp(argv[1], "aodv-leave-group") == 0){
        nsaddr_t mcast_addr = atoi(argv[2]);
        if (mcast_addr < IP_MULTICAST) return TCL_ERROR;
        aodv_mt_entry *mt = mtable.mt_lookup(mcast_addr);
        if (mt == 0 || mt->mt_node_status != ON_GROUP) return TCL_OK;
        if (mt->mt_grp_leader_addr != index) mt_prune(mt->mt_dst);
        else {
            mt->mt_node_status = ON_TREE;
            mt->mt_grp_leader_addr = INFINITY8;
            selectLeader(mt, INFINITY8);
        }
        return TCL_OK;
    }
#endif

  }
  return Agent::command(argc, argv);
}

/* 
   Constructor
*/

AODV::AODV(nsaddr_t id) : Agent(PT_AODV),
			  btimer(this), htimer(this), ntimer(this), 
			  rtimer(this), lrtimer(this), rqueue(),
                          /*** added for multicast ***/
			  grphtimer(this), rtetimer(this),
			  prune_timer(this), p_timer(this)
                          /***************************/
{
 
                
  index = id;
  seqno = 2;
  bid = 1;

  LIST_INIT(&nbhead);
  LIST_INIT(&bihead);

#ifdef MULTICAST
  hello_timeout = 0;
  optimization_criteria = TWO_OTR_OPTIMIZATION; // added by mk for QoS-Gl migration
  qos_target = 0.020; 
  qos_margin = 0.005;
  alpha = 0.5; // added by mk for QoS-Gl migration
  LIST_INIT(&pihead);
  sendHello();
#endif

  logtarget = 0;
  ifqueue = 0;
}

/*
  Timers
*/

void
BroadcastTimer::handle(Event*) {
  agent->id_purge();
  Scheduler::instance().schedule(this, &intr, BCAST_ID_SAVE);
}

void
HelloTimer::handle(Event* p) {

#ifdef MULTICAST
   Packet::free((Packet *)p);
   agent->sendHello();
#else
   agent->sendHello();
   double interval = MinHelloInterval +
                 ((MaxHelloInterval - MinHelloInterval) * Random::uniform());
   assert(interval >= 0);
   Scheduler::instance().schedule(this, &intr, interval);
#endif

}

void
NeighborTimer::handle(Event*) {
  agent->nb_purge();

#ifdef MULTICAST
#ifdef PREDICTION
  agent->mt_link_purge();
#endif
  Scheduler::instance().schedule(this, &intr, 0.5);
#else
  Scheduler::instance().schedule(this, &intr, HELLO_INTERVAL);
#endif

}

void
RouteCacheTimer::handle(Event*) {
  agent->rt_purge();
#define FREQUENCY 0.5 // sec
  Scheduler::instance().schedule(this, &intr, FREQUENCY);
}

void
LocalRepairTimer::handle(Event* p)  {  // SRD: 5/4/99
aodv_rt_entry *rt;
struct hdr_ip *ih = HDR_IP( (Packet *)p);

   /* you get here after the timeout in a local repair attempt */
   /*	fprintf(stderr, "%s\n", __FUNCTION__); */


    rt = agent->rtable.rt_lookup(ih->daddr());
	
    if (rt && rt->rt_flags != RTF_UP) {
    // route is yet to be repaired
    // I will be conservative and bring down the route
    // and send route errors upstream.
    /* The following assert fails, not sure why */
    /* assert (rt->rt_flags == RTF_IN_REPAIR); */
		
      //rt->rt_seqno++;
      agent->rt_down(rt);
      // send RERR
#ifdef DEBUG
      fprintf(stderr,"Node %d: Dst - %d, failed local repair\n",index, rt->rt_dst);
#endif      
    }
    Packet::free((Packet *)p);
}


/*
   Broadcast ID Management  Functions
*/


void
AODV::id_insert(nsaddr_t id, u_int32_t bid) {
BroadcastID *b = new BroadcastID(id, bid);

 assert(b);
 b->expire = CURRENT_TIME + BCAST_ID_SAVE;
 LIST_INSERT_HEAD(&bihead, b, link);
}

/* SRD */
bool
AODV::id_lookup(nsaddr_t id, u_int32_t bid) {
BroadcastID *b = bihead.lh_first;
 
 // Search the list for a match of source and bid
 for( ; b; b = b->link.le_next) {
   if ((b->src == id) && (b->id == bid))
     return true;     
 }
 return false;
}

void
AODV::id_purge() {
BroadcastID *b = bihead.lh_first;
BroadcastID *bn;
double now = CURRENT_TIME;

 for(; b; b = bn) {
   bn = b->link.le_next;
   if(b->expire <= now) {
     LIST_REMOVE(b,link);
     delete b;
   }
 }
}

/*
  Helper Functions
*/

double
AODV::PerHopTime(aodv_rt_entry *rt) {
int num_non_zero = 0, i;
double total_latency = 0.0;

 if (!rt)
   return ((double) NODE_TRAVERSAL_TIME );
	
 for (i=0; i < MAX_HISTORY; i++) {
   if (rt->rt_disc_latency[i] > 0.0) {
      num_non_zero++;
      total_latency += rt->rt_disc_latency[i];
   }
 }
 if (num_non_zero > 0)
   return(total_latency / (double) num_non_zero);
 else
   return((double) NODE_TRAVERSAL_TIME);

}

/*
  Link Failure Management Functions
*/

static void
aodv_rt_failed_callback(Packet *p, void *arg) {
  ((AODV*) arg)->rt_ll_failed(p);
}

/*
 * This routine is invoked when the link-layer reports a route failed.
 */
void
AODV::rt_ll_failed(Packet *p) {
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
aodv_rt_entry *rt;
nsaddr_t broken_nbr = ch->next_hop_;

#ifndef AODV_LINK_LAYER_DETECTION
 drop(p, DROP_RTR_MAC_CALLBACK);
#else 

 /*
  * Non-data packets and Broadcast Packets can be dropped.
  */
  if(! DATA_PACKET(ch->ptype()) ||
     (u_int32_t) ih->daddr() == IP_BROADCAST) {
    drop(p, DROP_RTR_MAC_CALLBACK);
    return;
  }
  log_link_broke(p);
	if((rt = rtable.rt_lookup(ih->daddr())) == 0) {
    drop(p, DROP_RTR_MAC_CALLBACK);
    return;
  }
  log_link_del(ch->next_hop_);

#ifdef IMPROVEMENT
  if (rt->rt_flags != RTF_DOWN && rt->rt_nexthop != ch->next_hop_){
    ch->next_hop_ = rt->rt_nexthop;
    Scheduler::instance().schedule(target_, p, 0.);
    return;
   }
#endif

#ifdef AODV_LOCAL_REPAIR
  /* if the broken link is closer to the dest than source, 
     attempt a local repair. Otherwise, bring down the route. */


  if (ch->num_forwards() > rt->rt_hops) {
    local_rt_repair(rt, p); // local repair
    // retrieve all the packets in the ifq using this link,
    // queue the packets for which local repair is done, 
    return;
  }
  else	
#endif // LOCAL REPAIR	
  {

#ifdef IMPROVEMENT
     if (rt->rt_flags != RTF_DOWN && 
        (rt->rt_retry_pid < ch->uid() || rt->rt_retry_times == 0)){     
       if (rt->rt_retry_times == 0) rt->rt_retry_times = 1;
       if (rt->rt_retry_pid < ch->uid()) rt->rt_retry_pid = ch->uid();
       ch->next_hop_ = rt->rt_nexthop;
       Scheduler::instance().schedule(target_, p, 0.);
       return;
     }
#endif

    drop(p, DROP_RTR_MAC_CALLBACK);
    // Do the same thing for other packets in the interface queue using the
    // broken link -Mahesh
while((p = ifqueue->filter(broken_nbr))) {
     drop(p, DROP_RTR_MAC_CALLBACK);
    }	
    nb_delete(broken_nbr);

#ifdef MULTICAST
    handle_link_failure(broken_nbr);
#endif

  }

#endif // LINK LAYER DETECTION
}

void
AODV::handle_link_failure(nsaddr_t id) {
aodv_rt_entry *rt, *rtn;
Packet *rerr = Packet::alloc();
struct hdr_aodv_error *re = HDR_AODV_ERROR(rerr);

 re->DestCount = 0;
 for(rt = rtable.head(); rt; rt = rtn) {  // for each rt entry
   rtn = rt->rt_link.le_next; 
   if ((rt->rt_hops != INFINITY2) && (rt->rt_nexthop == id) ) {
     assert (rt->rt_flags == RTF_UP);
     assert((rt->rt_seqno%2) == 0);
 
#ifndef MULTICAST
     rt->rt_seqno++;
#endif

     re->unreachable_dst[re->DestCount] = rt->rt_dst;
     re->unreachable_dst_seqno[re->DestCount] = rt->rt_seqno;
#ifdef DEBUG
     fprintf(stderr, "%s(%f): %d\t(%d\t%u\t%d)\n", __FUNCTION__, CURRENT_TIME,
		     index, re->unreachable_dst[re->DestCount],
		     re->unreachable_dst_seqno[re->DestCount], rt->rt_nexthop);
#endif // DEBUG
     re->DestCount += 1;
     rt_down(rt);
   }
   // remove the lost neighbor from all the precursor lists
   rt->pc_delete(id);
 }   

 if (re->DestCount > 0) {
#ifdef DEBUG
   fprintf(stderr, "%s(%f): %d\tsending RERR...\n", __FUNCTION__, CURRENT_TIME, index);
#endif // DEBUG
   sendError(rerr, false);
 }
 else {
   Packet::free(rerr);
 }
}

void
AODV::local_rt_repair(aodv_rt_entry *rt, Packet *p) {
#ifdef DEBUG
  fprintf(stderr,"%s: Dst - %d\n", __FUNCTION__, rt->rt_dst); 
#endif  
  // Buffer the packet 
  rqueue.enque(p);

  // mark the route as under repair 
  rt->rt_flags = RTF_IN_REPAIR;

  sendRequest(rt->rt_dst);

  // set up a timer interrupt
  Scheduler::instance().schedule(&lrtimer, p->copy(), rt->rt_req_timeout);
}

void
AODV::rt_update(aodv_rt_entry *rt, u_int32_t seqnum, u_int16_t metric,
	       	nsaddr_t nexthop, double expire_time) {

     rt->rt_seqno = seqnum;
     rt->rt_hops = metric;
     rt->rt_flags = RTF_UP;
     rt->rt_nexthop = nexthop;
     rt->rt_expire = expire_time;

#ifdef PREDICTION
     rt->rt_prevnode_warning = 0;
#endif
#ifdef IMPROVEMENT
     rt->rt_retry_pid = 0;
     rt->rt_retry_times = 0;
#endif
}

void
AODV::rt_down(aodv_rt_entry *rt) {
  /*
   *  Make sure that you don't "down" a route more than once.
   */

  if(rt->rt_flags == RTF_DOWN) {
    return;
  }

  // assert (rt->rt_seqno%2); // is the seqno odd?
  rt->rt_last_hop_count = rt->rt_hops;
  rt->rt_hops = INFINITY2;
  rt->rt_flags = RTF_DOWN;
  rt->rt_nexthop = 0;
  rt->rt_expire = 0;

} /* rt_down function */

/*
  Route Handling Functions
*/

void
AODV::rt_resolve(Packet *p) {
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
aodv_rt_entry *rt;

 /*
  *  Set the transmit failure callback.  That
  *  won't change.
  */
 ch->xmit_failure_ = aodv_rt_failed_callback;
 ch->xmit_failure_data_ = (void*) this;
 rt = rtable.rt_lookup(ih->daddr());
 if(rt == 0) {
	  rt = rtable.rt_add(ih->daddr());
 }
 
 /*
  * If the route is up, forward the packet 
  */

        //if (ch->uid() == 32 && index == 3) printf("---------rt flag is %d, %.9f\n", rt->rt_flags, CURRENT_TIME);

 if(rt->rt_flags == RTF_UP) {
   assert(rt->rt_hops != INFINITY2);

#ifdef PREDICTION
    double breakTime = 2000.0;

    if (ch->num_forwards() != 0 && ch->next_hop_ == index){
        Node *currentNode = Node::get_node_by_address(index);
        breakTime = currentNode->getTime(ch->prev_hop_);
        if (breakTime < 2000.0 && breakTime > CURRENT_TIME &&
            (breakTime - CURRENT_TIME < PREDICTION_TIME_FOR_UNICAST) &&
            (rt->rt_prevnode_warning == 0)){
            //printf("\nPREDICTION:: at %.9f on node %d prev node %d , dst %d, will break at %.9f\n", CURRENT_TIME, index, ch->prev_hop_, ih->daddr(), breakTime); 
            sendLPW(ch->prev_hop_, breakTime);
            rt->rt_prevnode_warning ++;
        }
    }
#endif

   forward(rt, p, NO_DELAY);
 }

#ifdef PREDICTION
 else if (rt->rt_flags == RTF_PREDICTION || rt->rt_flags == RTF_P_LINK) {
     if (rt->rt_expire <= CURRENT_TIME){
         rt->rt_seqno++;
         rt_down(rt);

         if (index == ih->saddr()) {
             rqueue.enque(p);
             sendRequest(ih->daddr());
         }
         else  forward(rt, p, NO_DELAY); //because this is only prediction broken time, try to forward it anyway.
     }
     else {
         forward(rt,p,NO_DELAY);
         if (index == ih->saddr()) {
              sendRequest(ih->daddr());
         }
     }
 }
#endif

 /*
  *  if I am the source of the packet, then do a Route Request.
  */
  else if(ih->saddr() == index) {
   rqueue.enque(p);
   sendRequest(rt->rt_dst);
 }
 /*
  *	A local repair is in progress. Buffer the packet. 
  */
 else if (rt->rt_flags == RTF_IN_REPAIR) {
   rqueue.enque(p);
 }

 /*
  * I am trying to forward a packet for someone else to which
  * I don't have a route.
  */
 else {

#ifdef MULTICAST
    sendMACT(rt->rt_dst, MACT_P, 0, ch->prev_hop_);
#endif
    
 Packet *rerr = Packet::alloc();
 struct hdr_aodv_error *re = HDR_AODV_ERROR(rerr);
 /* 
  * For now, drop the packet and send error upstream.
  * Now the route errors are broadcast to upstream
  * neighbors - Mahesh 09/11/99
  */	
 
   assert (rt->rt_flags == RTF_DOWN);
   re->DestCount = 0;
   re->unreachable_dst[re->DestCount] = rt->rt_dst;
   re->unreachable_dst_seqno[re->DestCount] = rt->rt_seqno;
   re->DestCount += 1;
#ifdef DEBUG
   fprintf(stderr, "%s: sending RERR...\n", __FUNCTION__);
#endif
   sendError(rerr, false);

   drop(p, DROP_RTR_NO_ROUTE);
 }

}

void
AODV::rt_purge() {
aodv_rt_entry *rt, *rtn;
double now = CURRENT_TIME;
double delay = 0.0;
Packet *p;

 for(rt = rtable.head(); rt; rt = rtn) {  // for each rt entry
   rtn = rt->rt_link.le_next;
   if (
#ifdef PREDICTION
     (rt->rt_flags == RTF_UP ||
      rt->rt_flags == RTF_P_LINK || rt->rt_flags == RTF_PREDICTION)
#else
     (rt->rt_flags == RTF_UP)
#endif
     && (rt->rt_expire < now)) {
   // if a valid route has expired, purge all packets from 
   // send buffer and invalidate the route.                    
	assert(rt->rt_hops != INFINITY2);
     while((p = rqueue.deque(rt->rt_dst))) {
#ifdef DEBUG
       fprintf(stderr, "%s: calling drop()\n",
                       __FUNCTION__);
#endif // DEBUG
       drop(p, DROP_RTR_NO_ROUTE);
     }
     rt->rt_seqno++;
     assert (rt->rt_seqno%2);
     rt_down(rt);
   }
   else if 
#ifdef PREDICTION
     (rt->rt_flags == RTF_UP ||
      rt->rt_flags == RTF_P_LINK || rt->rt_flags == RTF_PREDICTION)
#else
     (rt->rt_flags == RTF_UP)
#endif
  {

#ifdef PREDICTION
    if (rt->rt_flags == RTF_UP){
#endif
   // If the route is not expired,
   // and there are packets in the sendbuffer waiting,
   // forward them. This should not be needed, but this extra 
   // check does no harm.
     assert(rt->rt_hops != INFINITY2);
     while((p = rqueue.deque(rt->rt_dst))) {
       forward(rt, p, delay);
       delay += ARP_DELAY;
     }
#ifdef PREDICTION
    }
#endif
   } 
   else if (rqueue.find(rt->rt_dst))
   // If the route is down and 
   // if there is a packet for this destination waiting in
   // the sendbuffer, then send out route request. sendRequest
   // will check whether it is time to really send out request
   // or not.
   // This may not be crucial to do it here, as each generated 
   // packet will do a sendRequest anyway.

     sendRequest(rt->rt_dst); 
  }
}

/*
  Packet Reception Routines
*/

void
AODV::recv(Packet *p, Handler*) {
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);

 assert(initialized());
 //assert(p->incoming == 0);
 // XXXXX NOTE: use of incoming flag has been depracated; In order to track direction of pkt flow, direction_ in hdr_cmn is used instead. see packet.h for details.

#ifdef MULTICAST
 //added by mk for QoS GL-migration
 if((ch->ptype() == PT_CBR)&&(ih->daddr() > 0)) {
	 
   	u_int32_t seq_no;
   	double link_delay;
   	link_delay = calculateDelay(p, seq_no);
    //if(ih->saddr() != index) //XXX: Hack for senders receiving their own packets and updating their delay values ...
   	  updateUplinkDelay(ih->saddr(), ih->daddr(), seq_no, link_delay); 
   	//displayCbrPacketStats(p);
   	//displayNodeTreeStats(ih->daddr());
 	//displayNodeInfo(ih->daddr());
	if(isTreeLeaf(ih->daddr())) 
		sendQoSPacket(ih->daddr()); 
 }
  
 if(ih->saddr() != index || ch->num_forwards() != 0) {
    AODV_Neighbor *nb = nb_lookup(ch->prev_hop_);
    if(nb == 0) {
        nb_insert(ch->prev_hop_);
    }
    else {
        nb->nb_expire = CURRENT_TIME + ALLOWED_HELLO_LOSS * MaxHelloInterval;
    }
 }
#endif

 if(ch->ptype() == PT_AODV) {
   ih->ttl_ -= 1;
   recvAODV(p);
   return;
 }

 /*
  *  Must be a packet I'm originating...
  */
if((ih->saddr() == index) && (ch->num_forwards() == 0)) {
 /*
  * Add the IP Header
  */
   ch->size() += IP_HDR_LEN;
   // Added by Parag Dadhania && John Novatnack to handle broadcasting
   if ( (u_int32_t)ih->daddr() != IP_BROADCAST)
     ih->ttl_ = NETWORK_DIAMETER;
}
 /*
  *  I received a packet that I sent.  Probably
  *  a routing loop.
  */
else if(ih->saddr() == index) {
 
#ifdef MULTICAST
   if (ih->daddr() < IP_MULTICAST) drop(p, DROP_RTR_ROUTE_LOOP);
   else Packet::free(p);
#else
   drop(p, DROP_RTR_ROUTE_LOOP);
#endif

   return;
 }
 /*
  *  Packet I'm forwarding...
  */
 else {

#ifdef MULTICAST
  ih->ttl_--;
#else
 /*
  *  Check the TTL.  If it is zero, then discard.
  */
   if(--ih->ttl_ == 0) {
     drop(p, DROP_RTR_TTL);
     return;
   }
#endif

 }

#ifdef MULTICAST
 if ((u_int32_t)ih->daddr() < IP_MULTICAST) rt_resolve(p);
 else if ((u_int32_t)ih->daddr() == IP_BROADCAST) forward((aodv_rt_entry*) 0, p, NO_DELAY);
 else mt_resolve(p);
#else
// Added by Parag Dadhania && John Novatnack to handle broadcasting
 if ( (u_int32_t)ih->daddr() != IP_BROADCAST)
   rt_resolve(p);
 else
   forward((aodv_rt_entry*) 0, p, NO_DELAY);
#endif

}


void
AODV::recvAODV(Packet *p) {
struct hdr_aodv *ah = HDR_AODV(p);
struct hdr_ip *ih = HDR_IP(p);

 assert(ih->sport() == RT_PORT);
 assert(ih->dport() == RT_PORT);

 /*
  * Incoming Packets.
  */
 switch(ah->ah_type) {

 case AODVTYPE_RREQ:
   recvRequest(p);
   break;

 case AODVTYPE_RREP:
   recvReply(p);
   break;

 case AODVTYPE_RERR:
   recvError(p);
   break;

 case AODVTYPE_HELLO:
#ifdef MULTICAST
   Packet::free(p);
#else
   recvHello(p);
#endif
   break;

#ifdef PREDICTION
  case AODVTYPE_LPW:
  {
       struct hdr_aodv_lpw *rp = HDR_AODV_LPW(p);
       recvLPW(ih->saddr(), rp->breakTime);
       Packet::free(p);
  }
       break;

  case AODVTYPE_RPE:
       recvRPE(p);
       break;

  case AODVTYPE_LINK_RREQ:
       recvRequest_P(p);
       break;
#endif

#ifdef MULTICAST
 case AODVTYPE_MACT:
    recvMACT(p);
    break;

 case AODVTYPE_GRPH:
    recvMGRPH(p);
    break;

 case AODVTYPE_WARN:
    recvMWARN(p);
    break;

 case AODVTYPE_QOS: // added by mk for QoS GL-migration
    //XXX: Hack for packets that return from the sender to itself. In this case from grp-leader to itself.
    if(ih->saddr() != index)
 	  recvQoSPacket(p);       
 	else
 	  Packet::free(p);
	break;
#endif

 default:
   fprintf(stderr, "Invalid AODV type (%x)\n", ah->ah_type);
   exit(1);
 }

}


void
AODV::recvRequest(Packet *p) {
struct hdr_ip *ih = HDR_IP(p);
struct hdr_aodv_request *rq = HDR_AODV_REQUEST(p);
aodv_rt_entry *rt;

  /*
   * Drop if:
   *      - I'm the source
   *      - I recently heard this request.
   */

  if(rq->rq_src == index) {
#ifdef DEBUG
    fprintf(stderr, "%s: got my own REQUEST\n", __FUNCTION__);
#endif // DEBUG
    Packet::free(p);
    return;
  } 

 if (id_lookup(rq->rq_src, rq->rq_bcast_id)) {

#ifdef DEBUG
   fprintf(stderr, "%s: discarding request\n", __FUNCTION__);
#endif // DEBUG
 
   Packet::free(p);
   return;
 }

 /*
  * Cache the broadcast ID
  */

#ifndef PREDICTION
 id_insert(rq->rq_src, rq->rq_bcast_id);
#endif

 /* 
  * We are either going to forward the REQUEST or generate a
  * REPLY. Before we do anything, we make sure that the REVERSE
  * route is in the route table.
  */
 aodv_rt_entry *rt0; // rt0 is the reverse route 
   
   rt0 = rtable.rt_lookup(rq->rq_src);
   if(rt0 == 0) { /* if not in the route table */
   // create an entry for the reverse route.
     rt0 = rtable.rt_add(rq->rq_src);
   }

#ifdef PREDICTION
   if (rt0->rt_flags == RTF_P_LINK){
      Packet::free(p);
      return;
   }
   else id_insert(rq->rq_src, rq->rq_bcast_id);
#endif
  
   rt0->rt_expire = max(rt0->rt_expire, (CURRENT_TIME + REV_ROUTE_LIFE));

   if ( (rq->rq_src_seqno > rt0->rt_seqno ) ||
    	((rq->rq_src_seqno == rt0->rt_seqno) && 
	 (rq->rq_hop_count < rt0->rt_hops)) ) {
   // If we have a fresher seq no. or lesser #hops for the 
   // same seq no., update the rt entry. Else don't bother.
rt_update(rt0, rq->rq_src_seqno, rq->rq_hop_count, ih->saddr(),
     	       max(rt0->rt_expire, (CURRENT_TIME + REV_ROUTE_LIFE)) );
     if (rt0->rt_req_timeout > 0.0) {
     // Reset the soft state and 
     // Set expiry time to CURRENT_TIME + ACTIVE_ROUTE_TIMEOUT
     // This is because route is used in the forward direction,
     // but only sources get benefited by this change
       rt0->rt_req_cnt = 0;
       rt0->rt_req_timeout = 0.0; 
       rt0->rt_req_last_ttl = rq->rq_hop_count;
       rt0->rt_expire = CURRENT_TIME + ACTIVE_ROUTE_TIMEOUT;
     }

     /* Find out whether any buffered packet can benefit from the 
      * reverse route.
      * May need some change in the following code - Mahesh 09/11/99
      */
     assert (rt0->rt_flags == RTF_UP);
     Packet *buffered_pkt;
     double delay=0.0;
     while ((buffered_pkt = rqueue.deque(rt0->rt_dst))) {
       if (rt0 && (rt0->rt_flags == RTF_UP)) {
	 assert(rt0->rt_hops != INFINITY2);
         forward(rt0, buffered_pkt, NO_DELAY);
       }
     }
   } 
   // End for putting reverse route in rt table


 /*
  * We have taken care of the reverse route stuff.
  * Now see whether we can send a route reply. 
  */

#ifdef MULTICAST
  if (rq->rq_dst >= IP_MULTICAST){
    if (rq->rq_flags != RREQ_NO_FLAG && (CURRENT_TIME - rq->rq_timestamp) > 2*RREP_WAIT_TIME)
        {Packet::free(p); return;}

    switch (rq->rq_flags){
        case RREQ_NO_FLAG: recvMRQ_NOFLAG(p); return;
        case RREQ_J: recvMRQ_J(p); return;
        case RREQ_R: recvMRQ_R(p); return;
        case RREQ_JR: recvMRQ_JR(p); return;
        default: Packet::free(p); return;
    }
 }
#endif
 
 rt = rtable.rt_lookup(rq->rq_dst);

 // First check if I am the destination ..

 if(rq->rq_dst == index) {

#ifdef DEBUG
   fprintf(stderr, "%d - %s: destination sending reply\n",
                   index, __FUNCTION__);
#endif // DEBUG

               
   // Just to be safe, I use the max. Somebody may have
   // incremented the dst seqno.
   seqno = max(seqno, rq->rq_dst_seqno)+1;
   if (seqno%2) seqno++;

#ifdef MULTICAST
   sendReply(rq->rq_src,           // IP Destination
             rq->rq_flags,
             0,                    // Hop Count
             index,                // Dest IP Address
             seqno,                // Dest Sequence Num
             MY_ROUTE_TIMEOUT,     // Lifetime
             rq->rq_timestamp);     // timestamp
#else
   sendReply(rq->rq_src,           // IP Destination
             0,
             1,                    // Hop Count
             index,                // Dest IP Address
             seqno,                // Dest Sequence Num
             MY_ROUTE_TIMEOUT,     // Lifetime
             rq->rq_timestamp);    // timestamp
#endif
   /******************************/
 
   Packet::free(p);
 }

 // I am not the destination, but I may have a fresh enough route.

 else if (rt && (rt->rt_hops != INFINITY2) && 
	  	(rt->rt_seqno >= rq->rq_dst_seqno) ) {

   //assert (rt->rt_flags == RTF_UP);
   assert(rq->rq_dst == rt->rt_dst);
   //assert ((rt->rt_seqno%2) == 0);	// is the seqno even?

#ifdef MULTICAST
   sendReply(rq->rq_src,
             rq->rq_flags,
             rt->rt_hops,
             rq->rq_dst,
             rt->rt_seqno,
             (u_int32_t) (rt->rt_expire - CURRENT_TIME),
             //             rt->rt_expire - CURRENT_TIME,
             rq->rq_timestamp);     // timestamp
#else
   sendReply(rq->rq_src,
             0,
             rt->rt_hops + 1,
             rq->rq_dst,
             rt->rt_seqno,
             (u_int32_t) (rt->rt_expire - CURRENT_TIME),
             //             rt->rt_expire - CURRENT_TIME,
             rq->rq_timestamp);
#endif

   // Insert nexthops to RREQ source and RREQ destination in the
   // precursor lists of destination and source respectively
   rt->pc_insert(rt0->rt_nexthop); // nexthop to RREQ source
   rt0->pc_insert(rt->rt_nexthop); // nexthop to RREQ destination

#ifdef RREQ_GRAT_RREP  

   sendReply(rq->rq_dst,
             rq->rq_flags,
             rq->rq_hop_count,
             rq->rq_src,
             rq->rq_src_seqno,
	     (u_int32_t) (rt->rt_expire - CURRENT_TIME),
	     //             rt->rt_expire - CURRENT_TIME,
             rq->rq_timestamp);     // timestamp
#endif
   
// TODO: send grat RREP to dst if G flag set in RREQ using rq->rq_src_seqno, rq->rq_hop_counT
   
// DONE: Included gratuitous replies to be sent as per IETF aodv draft specification. As of now, G flag has not been dynamically used and is always set or reset in aodv-packet.h --- Anant Utgikar, 09/16/02.

	Packet::free(p);
 }
 /*
  * Can't reply. So forward the  Route Request
  */
 else {
   ih->saddr() = index;
   ih->daddr() = IP_BROADCAST;
   rq->rq_hop_count += 1;

#ifdef PREDICTION
   if (rt && rt->rt_flags == RTF_P_LINK) {
       struct hdr_aodv_request_link *rq1 = HDR_AODV_REQUEST_LINK(p);
       struct hdr_cmn *ch = HDR_CMN(p);
       
       ch->size() = IP_HDR_LEN + rq1->size();
       rq1->rq_type = AODVTYPE_LINK_RREQ;
       rq1->from = index;
       rq1->to = rt->rt_nexthop;
    }
#endif

   // Maximum sequence number seen en route
   if (rt) rq->rq_dst_seqno = max(rt->rt_seqno, rq->rq_dst_seqno);
   forward((aodv_rt_entry*) 0, p, DELAY);
 }

}


void
AODV::recvReply(Packet *p) {
//struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
struct hdr_aodv_reply *rp = HDR_AODV_REPLY(p);
aodv_rt_entry *rt;
char suppress_reply = 0;
double delay = 0.0;
	
#ifdef DEBUG
 fprintf(stderr, "%d - %s: received a REPLY\n", index, __FUNCTION__);
#endif // DEBUG

 /*
  *  Got a reply. So reset the "soft state" maintained for 
  *  route requests in the request table. We don't really have
  *  have a separate request table. It is just a part of the
  *  routing table itself. 
  */
 // Note that rp_dst is the dest of the data packets, not the
 // the dest of the reply, which is the src of the data packets.

#ifdef MULTICAST
 if (rp->rp_dst >= IP_MULTICAST){
    if (rp->rp_flags != RREP_NO_FLAG && (CURRENT_TIME - rp->rp_timestamp) > 2*RREP_WAIT_TIME)
        {Packet::free(p); return;}

    switch (rp->rp_flags){
        case RREP_NO_FLAG: break;
        case RREP_J: recvMRP_J(p); return;
        case RREP_R: recvMRP_R(p); return;
        case RREP_JR: recvMRP_JR(p); return;
        default: Packet::free(p); return;
    }
 }

 rp->rp_hop_count++;
#endif

  rt = rtable.rt_lookup(rp->rp_dst);
        
 /*
  *  If I don't have a rt entry to this host... adding
  */
 if(rt == 0) {
   rt = rtable.rt_add(rp->rp_dst);
 }

#ifdef PREDICTION
   struct hdr_cmn *ch = HDR_CMN(p); 
   if ((rt->rt_flags == RTF_P_LINK) &&
        rt->rt_nexthop == ch->prev_hop_){
       Packet::free(p);
       return;
   }
#endif

 /*
  * Add a forward route table entry... here I am following 
  * Perkins-Royer AODV paper almost literally - SRD 5/99
  */

 if ( (rt->rt_seqno < rp->rp_dst_seqno) ||   // newer route 
      ((rt->rt_seqno == rp->rp_dst_seqno) &&  
       (rt->rt_hops > rp->rp_hop_count)) ) { // shorter or better route
	
  // Update the rt entry 
  rt_update(rt, rp->rp_dst_seqno, rp->rp_hop_count,
		rp->rp_src, CURRENT_TIME + rp->rp_lifetime);

  // reset the soft state
  rt->rt_req_cnt = 0;
  rt->rt_req_timeout = 0.0; 
  rt->rt_req_last_ttl = rp->rp_hop_count;
  
if (ih->daddr() == index) { // If I am the original source
  // Update the route discovery latency statistics
  // rp->rp_timestamp is the time of request origination
		
    rt->rt_disc_latency[rt->hist_indx] = (CURRENT_TIME - rp->rp_timestamp)
                                         / (double) rp->rp_hop_count;
    // increment indx for next time
    rt->hist_indx = (rt->hist_indx + 1) % MAX_HISTORY;
  }	

  /*
   * Send all packets queued in the sendbuffer destined for
   * this destination. 
   * XXX - observe the "second" use of p.
   */
  Packet *buf_pkt;
  while((buf_pkt = rqueue.deque(rt->rt_dst))) {
    if(rt->rt_hops != INFINITY2) {
          assert (rt->rt_flags == RTF_UP);
    // Delay them a little to help ARP. Otherwise ARP 
    // may drop packets. -SRD 5/23/99

      forward(rt, buf_pkt, delay);
      delay += ARP_DELAY;
    }
  }
 }
 else {
  suppress_reply = 1;
 }

 /*
  * If reply is for me, discard it.
  */

if(ih->daddr() == index || suppress_reply) {
   Packet::free(p);
 }
 /*
  * Otherwise, forward the Route Reply.
  */
 else {
 // Find the rt entry
aodv_rt_entry *rt0 = rtable.rt_lookup(ih->daddr());
   // If the rt is up, forward
   if(rt0 && (rt0->rt_hops != INFINITY2)) {
        assert (rt0->rt_flags == RTF_UP);

#ifndef MULTICAST
     rp->rp_hop_count += 1;
#endif

     rp->rp_src = index;
     forward(rt0, p, NO_DELAY);
     // Insert the nexthop towards the RREQ source to 
     // the precursor list of the RREQ destination
     rt->pc_insert(rt0->rt_nexthop); // nexthop to RREQ source
     
   }
   else {
   // I don't know how to forward .. drop the reply. 
#ifdef DEBUG
     fprintf(stderr, "%s: dropping Route Reply\n", __FUNCTION__);
#endif // DEBUG
     drop(p, DROP_RTR_NO_ROUTE);
   }
 }
}


void
AODV::recvError(Packet *p) {
struct hdr_ip *ih = HDR_IP(p);
struct hdr_aodv_error *re = HDR_AODV_ERROR(p);
aodv_rt_entry *rt;
u_int8_t i;
Packet *rerr = Packet::alloc();
struct hdr_aodv_error *nre = HDR_AODV_ERROR(rerr);

 nre->DestCount = 0;

 for (i=0; i<re->DestCount; i++) {
 // For each unreachable destination
   rt = rtable.rt_lookup(re->unreachable_dst[i]);
   if ( rt && (rt->rt_hops != INFINITY2) &&
	(rt->rt_nexthop == ih->saddr()) &&
     	(rt->rt_seqno <= re->unreachable_dst_seqno[i]) ) {

#ifdef PREDICTION
        assert(rt->rt_flags == RTF_UP ||
               rt->rt_flags == RTF_P_LINK || rt->rt_flags == RTF_PREDICTION); 
#else
        assert(rt->rt_flags == RTF_UP);
#endif

        assert((rt->rt_seqno%2) == 0); // is the seqno even?
#ifdef DEBUG
     fprintf(stderr, "%s(%f): %d\t(%d\t%u\t%d)\t(%d\t%u\t%d)\n", __FUNCTION__,CURRENT_TIME,
        	     index, rt->rt_dst, rt->rt_seqno, rt->rt_nexthop,
		     re->unreachable_dst[i],re->unreachable_dst_seqno[i],
	             ih->saddr());
#endif // DEBUG
     	rt->rt_seqno = re->unreachable_dst_seqno[i];
     	rt_down(rt);

   // Not sure whether this is the right thing to do
   Packet *pkt;
	while((pkt = ifqueue->filter(ih->saddr()))) {
        	drop(pkt, DROP_RTR_MAC_CALLBACK);
     	}

     // if precursor list non-empty add to RERR and delete the precursor list
     	if (!rt->pc_empty()) {
     		nre->unreachable_dst[nre->DestCount] = rt->rt_dst;
     		nre->unreachable_dst_seqno[nre->DestCount] = rt->rt_seqno;
     		nre->DestCount += 1;
		rt->pc_delete();
     	}
   }
 } 

 if (nre->DestCount > 0) {
#ifdef DEBUG
   fprintf(stderr, "%s(%f): %d\t sending RERR...\n", __FUNCTION__, CURRENT_TIME, index);
#endif // DEBUG
   sendError(rerr);
 }
 else {
   Packet::free(rerr);
 }

 Packet::free(p);
}


/*
   Packet Transmission Routines
*/

void
AODV::forward(aodv_rt_entry *rt, Packet *p, double delay) {
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);


 if(ih->ttl_ == 0) {

#ifdef DEBUG
  fprintf(stderr, "%s: calling drop()\n", __PRETTY_FUNCTION__);
#endif // DEBUG
 
  drop(p, DROP_RTR_TTL);
  return;
 }

 /*** added for multicast ***/
 ch->prev_hop_ = index;
 /**************************/
 
 if (rt) {
#ifdef PREDICTION
   assert(rt->rt_flags == RTF_UP ||
          rt->rt_flags == RTF_P_LINK || rt->rt_flags == RTF_PREDICTION);

   if (rt->rt_flags == RTF_UP)
       rt->rt_expire = CURRENT_TIME + ACTIVE_ROUTE_TIMEOUT;
#else
   assert(rt->rt_flags == RTF_UP);
   rt->rt_expire = CURRENT_TIME + ACTIVE_ROUTE_TIMEOUT;
#endif

   ch->next_hop_ = rt->rt_nexthop;
   ch->addr_type() = NS_AF_INET;
   ch->direction() = hdr_cmn::DOWN;       //important: change the packet's direction
 }
 else { // if it is a broadcast packet
   // assert(ch->ptype() == PT_AODV); // maybe a diff pkt type like gaf
   assert(ih->daddr() == (nsaddr_t) IP_BROADCAST);
   ch->addr_type() = NS_AF_NONE;
   ch->direction() = hdr_cmn::DOWN;       //important: change the packet's direction
 }

if (ih->daddr() == (nsaddr_t) IP_BROADCAST) {
 // If it is a broadcast packet
   assert(rt == 0);
   /*
    *  Jitter the sending of broadcast packets by 10ms
    */

#ifdef MULTICAST
   controlNextHello();
#endif
   
   Scheduler::instance().schedule(target_, p,
      				   0.01 * Random::uniform());
 }
 else { // Not a broadcast packet 
   if(delay > 0.0) {
     Scheduler::instance().schedule(target_, p, delay);
   }
   else {
   // Not a broadcast packet, no delay, send immediately
     Scheduler::instance().schedule(target_, p, 0.);
   }
 }

}


void
AODV::sendRequest(nsaddr_t dst) {
// Allocate a RREQ packet 
Packet *p = Packet::alloc();
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
struct hdr_aodv_request *rq = HDR_AODV_REQUEST(p);
aodv_rt_entry *rt = rtable.rt_lookup(dst);

 assert(rt);

 /*
  *  Rate limit sending of Route Requests. We are very conservative
  *  about sending out route requests. 
  */

 if (rt->rt_flags == RTF_UP) {
   assert(rt->rt_hops != INFINITY2);
   Packet::free((Packet *)p);
   return;
 }

 if (rt->rt_req_timeout > CURRENT_TIME) {
   Packet::free((Packet *)p);
   return;
 }

 // rt_req_cnt is the no. of times we did network-wide broadcast
 // RREQ_RETRIES is the maximum number we will allow before 
 // going to a long timeout.

 if (rt->rt_req_cnt > RREQ_RETRIES) {
   rt->rt_req_timeout = CURRENT_TIME + MAX_RREQ_TIMEOUT;
   rt->rt_req_cnt = 0;

#ifdef MULTICAST
   rt->rt_req_times = 0;
#endif

  Packet *buf_pkt;
   while ((buf_pkt = rqueue.deque(rt->rt_dst))) {
       drop(buf_pkt, DROP_RTR_NO_ROUTE);
   }
   Packet::free((Packet *)p);
   return;
 }

#ifdef DEBUG
   fprintf(stderr, "%2d sending Route Request, dst: %d\n",
                    index, rt->rt_dst);
#endif // DEBUG

 // Determine the TTL to be used this time. 
 // Dynamic TTL evaluation - SRD

 rt->rt_req_last_ttl = max(rt->rt_req_last_ttl,rt->rt_last_hop_count);

#ifdef MULTICAST
 rt->rt_req_times ++;
#endif

 if (0 == rt->rt_req_last_ttl) {
 // first time query broadcast
   ih->ttl_ = TTL_START;
 }
 else {
 // Expanding ring search.
   if (rt->rt_req_last_ttl < TTL_THRESHOLD)
     ih->ttl_ = rt->rt_req_last_ttl + TTL_INCREMENT;
   else {
   // network-wide broadcast
     ih->ttl_ = NETWORK_DIAMETER;
     rt->rt_req_cnt += 1;
   }
 }

 // remember the TTL used  for the next time
 rt->rt_req_last_ttl = ih->ttl_;

 // PerHopTime is the roundtrip time per hop for route requests.
 // The factor 2.0 is just to be safe .. SRD 5/22/99
 // Also note that we are making timeouts to be larger if we have 
 // done network wide broadcast before. 

 rt->rt_req_timeout = 2.0 * (double) ih->ttl_ * PerHopTime(rt); 
 if (rt->rt_req_cnt > 0)
   rt->rt_req_timeout *= rt->rt_req_cnt;
 rt->rt_req_timeout += CURRENT_TIME;

 // Don't let the timeout to be too large, however .. SRD 6/8/99
 if (rt->rt_req_timeout > CURRENT_TIME + MAX_RREQ_TIMEOUT)
   rt->rt_req_timeout = CURRENT_TIME + MAX_RREQ_TIMEOUT;
 rt->rt_expire = 0;

#ifdef DEBUG
 fprintf(stderr, "(%2d) - %2d sending Route Request, dst: %d, tout %f ms\n",
	         ++route_request, 
		 index, rt->rt_dst, 
		 rt->rt_req_timeout - CURRENT_TIME);
#endif	// DEBUG
	

 // Fill out the RREQ packet 
 // ch->uid() = 0;
 ch->ptype() = PT_AODV;
 ch->size() = IP_HDR_LEN + rq->size();
 ch->iface() = -2;
 ch->error() = 0;
 ch->addr_type() = NS_AF_NONE;
 ch->prev_hop_ = index;          // AODV hack

 ih->saddr() = index;
 ih->daddr() = IP_BROADCAST;
 ih->sport() = RT_PORT;
 ih->dport() = RT_PORT;

 // Fill up some more fields. 
 rq->rq_type = AODVTYPE_RREQ;
 rq->rq_flags = RREQ_NO_FLAG;
 rq->rq_hop_count = 1;
 rq->rq_bcast_id = bid++;
 rq->rq_dst = dst;
 rq->rq_dst_seqno = (rt ? rt->rt_seqno : 0);
 rq->rq_src = index;
 seqno += 2;
 assert ((seqno%2) == 0);
 rq->rq_src_seqno = seqno;
 rq->rq_timestamp = CURRENT_TIME;

#ifdef PREDICTION
 if (rt->rt_flags == RTF_P_LINK){
     struct hdr_aodv_request_link *rqlk = HDR_AODV_REQUEST_LINK(p);
     rqlk->rq_type = AODVTYPE_LINK_RREQ;
     rqlk->from = index;
     rqlk->to = rt->rt_nexthop;
 }
#endif

#ifdef MULTICAST
 if (rq->rq_dst >= IP_MULTICAST && rt->rt_req_times == 1){
    aodv_glt_entry *glt = gltable.glt_lookup(rq->rq_dst);
    if (glt && glt->glt_expire > CURRENT_TIME){
            ch->addr_type() = NS_AF_INET;
            ch->next_hop_ = glt->glt_next_hop;
            ih->daddr() = glt->glt_grp_leader_addr;
    }
 }

 if (ih->daddr() == IP_BROADCAST) controlNextHello();
#endif
 
 Scheduler::instance().schedule(target_, p, 0.);
}

/*please note, the sendReply auguments is not the same as original one 
because of adding multicast functions*/
void
AODV::sendReply(nsaddr_t ipdst, u_int8_t flags, u_int32_t hop_count, nsaddr_t rpdst,
                u_int32_t rpseq, u_int32_t lifetime, double timestamp,
                u_int8_t hops_grp_leader, nsaddr_t grp_leader_addr) {
Packet *p = Packet::alloc();
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
struct hdr_aodv_reply *rp = HDR_AODV_REPLY(p);
aodv_rt_entry *rt = rtable.rt_lookup(ipdst);

#ifdef DEBUG
fprintf(stderr, "sending Reply from %d at %.9f\n", index, Scheduler::instance().clock());
#endif // DEBUG
 assert(rt);

 rp->rp_type = AODVTYPE_RREP;

 /*** added for multicast ***/
 rp->rp_flags = flags;
 /***************************/

 //rp->rp_flags = 0x00;
 rp->rp_hop_count = hop_count;
 rp->rp_dst = rpdst;
 rp->rp_dst_seqno = rpseq;
 rp->rp_src = index;
 rp->rp_lifetime = lifetime;
 rp->rp_timestamp = timestamp;
   
 // ch->uid() = 0;
 ch->ptype() = PT_AODV;
 ch->size() = IP_HDR_LEN + rp->size();
 ch->iface() = -2;
 ch->error() = 0;
 ch->addr_type() = NS_AF_INET;
 ch->next_hop_ = rt->rt_nexthop;
 ch->prev_hop_ = index;          // AODV hack
 ch->direction() = hdr_cmn::DOWN;

 ih->saddr() = index;
 ih->daddr() = ipdst;
 ih->sport() = RT_PORT;
 ih->dport() = RT_PORT;
 ih->ttl_ = NETWORK_DIAMETER;

#ifdef MULTICAST
 if (rp->rp_dst >= IP_MULTICAST && flags == RREP_J){
     struct hdr_aodv_reply_ext *rpe= (struct hdr_aodv_reply_ext *)(HDR_AODV_REPLY(p) + rp->size());
     rpe->type = AODVTYPE_RREP_EXT;
     rpe->length = AODVTYPE_RREP_EXT_LEN;
     rpe->hops_grp_leader = hops_grp_leader;
     rpe->grp_leader_addr = grp_leader_addr;
     ch->size()+= rpe->size();
 }
#endif

 Scheduler::instance().schedule(target_, p, 0.0);

}

void
AODV::sendError(Packet *p, bool jitter) {
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
struct hdr_aodv_error *re = HDR_AODV_ERROR(p);
    
#ifdef ERROR
fprintf(stderr, "sending Error from %d at %.2f\n", index, Scheduler::instance().clock());
#endif // DEBUG

 re->re_type = AODVTYPE_RERR;
 //re->reserved[0] = 0x00; re->reserved[1] = 0x00;
 // DestCount and list of unreachable destinations are already filled

 // ch->uid() = 0;
 ch->ptype() = PT_AODV;
 ch->size() = IP_HDR_LEN + re->size();
 ch->iface() = -2;
 ch->error() = 0;
 ch->addr_type() = NS_AF_NONE;
 ch->next_hop_ = 0;
 ch->prev_hop_ = index;          // AODV hack
 ch->direction() = hdr_cmn::DOWN;       //important: change the packet's direction

 ih->saddr() = index;
 ih->daddr() = IP_BROADCAST;
 ih->sport() = RT_PORT;
 ih->dport() = RT_PORT;
 ih->ttl_ = 1;

#ifdef MULTICAST
 controlNextHello();
#endif

 // Do we need any jitter? Yes
 if (jitter)
 	Scheduler::instance().schedule(target_, p, 0.01*Random::uniform());
 else
 	Scheduler::instance().schedule(target_, p, 0.0);

}


/*
   Neighbor Management Functions
*/

void
AODV::sendHello() {

#ifdef MULTICAST
aodv_mt_entry *mt;
bool cont = false;
for(mt = mtable.head(); mt; mt = mt->mt_link.le_next){
   if (mt->mt_node_status != NOT_ON_TREE){
     cont = true;
     break;
   }
} 

if (!cont) return;

if (hello_timeout > CURRENT_TIME) return;

controlNextHello();
#endif

Packet *p = Packet::alloc();
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
struct hdr_aodv_reply *rh = HDR_AODV_REPLY(p);

#ifdef DEBUG
fprintf(stderr, "sending Hello from %d at %.2f\n", index, Scheduler::instance().clock());
#endif // DEBUG

 rh->rp_type = AODVTYPE_HELLO;
 //rh->rp_flags = 0x00;
 rh->rp_hop_count = 1;
 rh->rp_dst = index;
 rh->rp_dst_seqno = seqno;
 rh->rp_lifetime = (1 + ALLOWED_HELLO_LOSS) * HELLO_INTERVAL;

 // ch->uid() = 0;
 ch->ptype() = PT_AODV;
 ch->size() = IP_HDR_LEN + rh->size();
 ch->iface() = -2;
 ch->error() = 0;
 ch->addr_type() = NS_AF_NONE;
 ch->prev_hop_ = index;          // AODV hack

 ih->saddr() = index;
 ih->daddr() = IP_BROADCAST;
 ih->sport() = RT_PORT;
 ih->dport() = RT_PORT;
 ih->ttl_ = 1;

#ifdef MULTICAST
 Scheduler::instance().schedule(target_, p, 0.01*Random::uniform());
#else 
 Scheduler::instance().schedule(target_, p, 0.0);
#endif
}


void
AODV::recvHello(Packet *p){

#ifdef MULTICAST
  Packet::free(p);
#else
//struct hdr_ip *ih = HDR_IP(p);
struct hdr_aodv_reply *rp = HDR_AODV_REPLY(p);
AODV_Neighbor *nb;

 nb = nb_lookup(rp->rp_dst);
 if(nb == 0) {
   nb_insert(rp->rp_dst);
 }
 else {
   nb->nb_expire = CURRENT_TIME +
                   (1.5 * ALLOWED_HELLO_LOSS * HELLO_INTERVAL);
 }
 Packet::free(p);
#endif

}

void
AODV::nb_insert(nsaddr_t id) {
AODV_Neighbor *nb = new AODV_Neighbor(id);

 assert(nb);

#ifdef MULTICAST
 nb->nb_expire = CURRENT_TIME + ALLOWED_HELLO_LOSS * MaxHelloInterval;
#else
 nb->nb_expire = CURRENT_TIME +
                (1.5 * ALLOWED_HELLO_LOSS * HELLO_INTERVAL);
#endif

 LIST_INSERT_HEAD(&nbhead, nb, nb_link);
 seqno += 2;             // set of neighbors changed
 assert ((seqno%2) == 0);
}


AODV_Neighbor*
AODV::nb_lookup(nsaddr_t id) {
AODV_Neighbor *nb = nbhead.lh_first;

 for(; nb; nb = nb->nb_link.le_next) {
   if(nb->nb_addr == id) break;
 }
 return nb;
}


/*
 * Called when we receive *explicit* notification that a Neighbor
 * is no longer reachable.
 */
void
AODV::nb_delete(nsaddr_t id) {
AODV_Neighbor *nb = nbhead.lh_first;

 log_link_del(id);
 seqno += 2;     // Set of neighbors changed
 assert ((seqno%2) == 0);

 for(; nb; nb = nb->nb_link.le_next) {
   if(nb->nb_addr == id) {
     LIST_REMOVE(nb,nb_link);
     delete nb;
     break;
   }
 }

#ifndef MULTICAST
 handle_link_failure(id);
#endif

}


/*
 * Purges all timed-out Neighbor Entries - runs every
 * HELLO_INTERVAL * 1.5 seconds.
 */
void
AODV::nb_purge() {
AODV_Neighbor *nb = nbhead.lh_first;
AODV_Neighbor *nbn;
double now = CURRENT_TIME;

 for(; nb; nb = nbn) {
   nbn = nb->nb_link.le_next;
   if(nb->nb_expire <= now) {
     nb_delete(nb->nb_addr);

#ifdef MULTICAST
     mt_nb_fail(nb->nb_addr);
#endif

   }
 }
}

/*** added for prediction for unicast ***/
void
AODV::recvLPW(nsaddr_t prev, double breakTime)
{

    aodv_rt_entry *rt = rtable.head();
    Packet *p = Packet::alloc();
    struct hdr_aodv_rpe *rpe = HDR_AODV_RPE(p);

    rpe->breakTime = breakTime;
    rpe->DestCount = 0;

    for (; rt; rt = rt->rt_link.le_next){
       if (rt->rt_nexthop == prev && 
           rt->rt_flags != RTF_DOWN && rt->rt_flags != RTF_P_LINK &&
           rt->rt_expire > breakTime) {
          
           rt->rt_flags = RTF_P_LINK;
           rt->rt_expire = breakTime;
      
           rpe->vulnerable_dst[rpe->DestCount] = rt->rt_dst;
           rpe->vulnerable_dst_seqno[rpe->DestCount] = rt->rt_seqno;
           rpe->DestCount += 1;
           printf("recvLPW: %.9f, at node %d, to dest %d, with nexthop %d, route will break at %.9f\n", CURRENT_TIME, index, rt->rt_dst, prev, breakTime);
        }
    }

    if (rpe->DestCount > 0) sendRPE(p);
    else Packet::free(p);

}

void
AODV::sendLPW(nsaddr_t prev, double breakTime)
{

        Packet *p = Packet::alloc();
        struct hdr_cmn *ch = HDR_CMN(p);
        struct hdr_ip *ih = HDR_IP(p);
        struct hdr_aodv_lpw *rp = HDR_AODV_LPW(p);

        ch->ptype() = PT_AODV;
        ch->size() = IP_HDR_LEN + rp->size();
        ch->iface() = -2;
        ch->error() = 0;
        ch->addr_type() = NS_AF_INET;
        ch->prev_hop_ = index;          // AODV hack
        ch->next_hop_ = prev;

        ih->saddr() = index;
        ih->daddr() = prev;
        ih->sport() = RT_PORT;
        ih->dport() = RT_PORT;
        ih->ttl_ = 1;

        rp->rp_type = AODVTYPE_LPW;
        rp->rp_dst = prev;
        rp->breakTime = breakTime;

        Scheduler::instance().schedule(target_, p, 0.0);

}
void
AODV::sendRPE(Packet *p)
{
        struct hdr_cmn *ch = HDR_CMN(p);
        struct hdr_ip *ih = HDR_IP(p);
        struct hdr_aodv_rpe *rp = HDR_AODV_RPE(p);

        // ch->uid() = 0;
        ch->ptype() = PT_AODV;
        ch->size() = IP_HDR_LEN + rp->size();
        ch->iface() = -2;
        ch->error() = 0;
        ch->addr_type() = NS_AF_NONE;
        ch->next_hop_ = MAC_BROADCAST;
        ch->prev_hop_ = index;          // AODV hack

        ih->saddr() = index;
        ih->daddr() = IP_BROADCAST;
        ih->sport() = RT_PORT;
        ih->dport() = RT_PORT;
        ih->ttl_ = 1;

        rp->rp_type = AODVTYPE_RPE;

#ifdef MULTICAST
        controlNextHello();
#endif

        //send with jitter
        Scheduler::instance().schedule(target_, p, 0.01*Random::uniform());
}

void
AODV::recvRPE(Packet *p)
{
    struct hdr_ip *ih = HDR_IP(p);
    struct hdr_aodv_rpe *rpe = HDR_AODV_RPE(p);
    aodv_rt_entry *rt;
    u_int8_t i;
    Packet *np = Packet::alloc();
    struct hdr_aodv_rpe *nrpe = HDR_AODV_RPE(np);

    nrpe->DestCount = 0;
    nrpe->breakTime = rpe->breakTime;

    for (i=0; i<rpe->DestCount; i++) {
        // For each vulnerable route
        rt = rtable.rt_lookup(rpe->vulnerable_dst[i]);
        if (rt && (rt->rt_nexthop == ih->saddr()) &&
            (rt->rt_seqno <= rpe->vulnerable_dst_seqno[i]) &&
            (rt->rt_flags == RTF_UP) &&
            (rt->rt_expire >  rpe->breakTime)) {

            rt->rt_seqno = rpe->vulnerable_dst_seqno[i];
            rt->rt_expire = rpe->breakTime;
            rt->rt_flags = RTF_PREDICTION;

            nrpe->vulnerable_dst[nrpe->DestCount] = rt->rt_dst;
            nrpe->vulnerable_dst_seqno[nrpe->DestCount] = rt->rt_seqno;
            nrpe->DestCount += 1;

           printf("recvRPE: %.9f, at node %d, to dest %d, with nexthop %d, route will break at other link at %.9f\n", CURRENT_TIME, index, rt->rt_dst, ih->saddr(), rpe->breakTime);

        }
    }

    if (nrpe->DestCount > 0) sendRPE(np);
    else Packet::free(np);

    Packet::free(p);
}

void
AODV::recvRequest_P(Packet *p)
{
        struct hdr_ip *ih = HDR_IP(p);
        struct hdr_aodv_request_link *rqlk = HDR_AODV_REQUEST_LINK(p);

        if (ih->saddr()== rqlk->from && rqlk->to == index) Packet::free(p);
        else    recvRequest(p);
}
/**************************************/


