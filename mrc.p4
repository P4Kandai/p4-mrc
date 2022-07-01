/* -*- P4_16 -*- */  
#include <core.p4> 
//#include <v1model.p4>
#include "/home/p4/tutorials/vm/p4c/p4include/v1model.p4" 
const bit<16> TYPE_IPV4 = 0x800; 
const bit<16> TYPE_BP = 0x9999; 
const bit<16> TYPE_FD = 0x9998; 
const bit<8> UDP = 16; 
 
#define CLONE_SESSION 100 
#define CHECK_TIME 1000000 
#define MAX_PORT 6
#define D 10000     
#define PRE_T 3
#define C 0 
 
typedef bit<9>  egressSpec_t;          
typedef bit<48> macAddr_t; 
typedef bit<32> ip4Addr_t; 
typedef bit<48> time_t; 
typedef bit<32> mytime_t; 
 
/************************************************************************* 
*********************** R E G S T E R S  *********************************  
*************************************************************************/ 
register<time_t>(MAX_PORT) port_time; 
register<bit<5>>(MAX_PORT) port_count;
register<bit<8>>(MAX_PORT) check_port;
register<bit<8>>(1) failed_port; 

register<bit<1>>(1) clone_flg_in;
register<time_t>(MAX_PORT) port_surv;
register<bit<1>>(1) adja_ok_check;  
register<time_t>(MAX_PORT) fail_occur;

/************************************************************************* 
*********************** H E A D E R S  ***********************************  
*************************************************************************/ 
 
@controller_header("packet_out") 
header packet_out_header_t { 
    bit<9> egress_port; 
    bit<7> _pad; 
} 
 
@controller_header("packet_in") 
header packet_in_header_t { 
    bit<9> ingress_port; 
    bit<7> _pad; 
} 
 
header ethernet_t { 
    macAddr_t dstAddr; 
    macAddr_t srcAddr; 
    bit<16>   etherType; 
} 
 
header ipv4_t { 
    bit<4>    version; 
    bit<4>    ihl; 
    bit<8>    tos; 
    bit<16>   totalLen; 
    bit<16>   identification; 
    bit<3>    flags; 
    bit<13>   fragOffset; 
    bit<8>    ttl; 
    bit<8>    protocol; 
    bit<16>   hdrChecksum; 
    ip4Addr_t srcAddr; 
    ip4Addr_t dstAddr; 
    bit<32>   options; 
} 
 
header detect_t { 
    bit<32>     in_time;
    bit<6>      type;
    bit<8>      in_port;
    bit<1>      d_flg;
    bit<1>      r_flg;
} 
 
header backup_path_t { 
    bit<8>    config; 
    bit<16>   type; 
} 
 
header udp_t { 
    bit<16>  sport; 
    bit<16>  dport; 
    bit<16>  len; 
    bit<16>  chksum; 
} 
 
struct my_metadata_t { 
    bit<8> failed_port;
} 
struct metadata { 
    my_metadata_t my_metadata; 
} 
 
struct headers { 
    ethernet_t          ethernet; 
    ipv4_t              ipv4; 
    detect_t            detect; 
    udp_t               udp; 
    backup_path_t       bp; 
    packet_out_header_t packet_out; 
    packet_in_header_t  packet_in; 
} 
 
 
 
 
/************************************************************************* 
*********************** P A R S E R  *********************************** 
*************************************************************************/ 
 
parser MyParser(packet_in packet, 
                out headers hdr, 
                inout metadata meta, 
                inout standard_metadata_t standard_metadata) { 
 
    state start {
        transition parse_ethernet; 
    } 
    state parse_ethernet { 
        packet.extract(hdr.ethernet); 
        transition select(hdr.ethernet.etherType) { 
            TYPE_FD: parse_fd; 
            TYPE_BP: parse_bp; 
            TYPE_IPV4: parse_ipv4; 
            default  : accept; 
        } 
    } 
     
    state parse_bp { 
        packet.extract(hdr.detect); 
        transition accept; 
    } 
    state parse_fd { 
        packet.extract(hdr.bp); 
        transition select((bit<16>)hdr.bp.type) { 
            TYPE_IPV4 : parse_ipv4; 
            default   : accept; 
        } 
    } 
 
    state parse_ipv4 { 
        packet.extract(hdr.ipv4); 
        transition select(hdr.ipv4.protocol) { 
            UDP     : parse_udp; 
            default : accept; 
        } 
    } 
    state parse_udp { 
        packet.extract(hdr.udp); 
        transition accept; 
    }
} 
 
 
/************************************************************************* 
************   C H E C K S U M    V E R I F I C A T I O N   ************* 
*************************************************************************/ 
 
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {    
    apply {  } 
} 
 
 
/************************************************************************* 
**************  I N G R E S S   P R O C E S S I N G   ******************* 
*************************************************************************/ 
 
control MyIngress(inout headers hdr, 
                  inout metadata meta, 
                  inout standard_metadata_t standard_metadata) { 
 
    action drop() { 
        mark_to_drop(standard_metadata); 
    } 
     
    action myheader_add() { 
        hdr.bp.setValid(); 
        hdr.bp.type            = hdr.ethernet.etherType; 
        hdr.ethernet.etherType = TYPE_FD; 
    } 
 
    action adja_ok (bit<1> value) { 
        adja_ok_check.write(0, value); 
    } 
    table adja_check { 
        key = { 
            hdr.ipv4.dstAddr: exact; 
        } 
        actions = { 
            adja_ok; 
            NoAction; 
        } 
        size = 1024; 
        default_action = NoAction(); 
    } 
 
    action adja_host_ok (bit<1> value) { 
        adja_ok_check.write(0, value); 
    }     
    table adja_check_host { 
        key = { 
            hdr.ipv4.dstAddr: exact; 
        } 
        actions = { 
            adja_host_ok; 
            NoAction; 
        } 
        size = 1024; 
        default_action = NoAction(); 
    } 
 
    action set_Conf (bit<8> conf) { 
        hdr.ipv4.tos  = conf;
        hdr.bp.config = conf; 
    } 
    table MRC_conf { 
        key = { 
            meta.my_metadata.failed_port: exact; 
        } 
        actions = { 
            set_Conf; 
            NoAction; 
        } 
        size = 1024; 
        default_action = NoAction(); 
    } 
    table MRC_Nodeconf_search { 
        key = { 
            meta.my_metadata.failed_port: exact; 
        } 
        actions = { 
            set_Conf; 
            NoAction; 
        } 
        size = 1024; 
        default_action = NoAction(); 
    } 
 
    action phy_forward(macAddr_t dstAddr, macAddr_t srcAddr, egressSpec_t port) { 
        standard_metadata.egress_spec = port; 
        hdr.ethernet.srcAddr          = srcAddr; 
        hdr.ethernet.dstAddr          = dstAddr; 
    } 
    table phy_return { 
        key = { 
            hdr.ethernet.srcAddr: exact; 
        } 
        actions = { 
            phy_forward; 
            drop; 
        } 
        size = 1024; 
        default_action = drop(); 
    } 
     
     
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) { 
        standard_metadata.egress_spec = port; 
        hdr.ethernet.srcAddr          = hdr.ethernet.dstAddr; 
        hdr.ethernet.dstAddr          = dstAddr; 
        hdr.ipv4.ttl                  = hdr.ipv4.ttl - 1; 
    } 
    table ipv4_lpm { 
        key = { 
            hdr.ipv4.dstAddr : lpm; 
        } 
        actions = { 
            ipv4_forward; 
            drop; 
            NoAction; 
        } 
        size           = 1024; 
        default_action = NoAction(); 
    } 
     
    table confdst2port { 
        key = { 
            hdr.ipv4.dstAddr : lpm; 
            hdr.bp.config    : exact; 
        } 
        actions = { 
            ipv4_forward; 
            drop; 
        } 
        size           = 1024; 
        default_action = drop(); 
    } 

     
    apply { 
        bit<1> cln_flg; 
        time_t prt_srv; 
        clone_flg_in.read(cln_flg, 0); 
        bit<48> pre_time; 
        if (hdr.detect.isValid() && hdr.detect.type == 0 && hdr.detect.r_flg == 0) { 
            port_time.read(pre_time, (bit<32>)hdr.detect.in_port); 
            if (standard_metadata.ingress_global_timestamp - pre_time < D) { 
                drop(); 
            } 
        } 
        if (hdr.detect.isValid() && hdr.detect.type == 0 
            && hdr.detect.r_flg == 0) {
            prt_srv = standard_metadata.ingress_global_timestamp;
            port_surv.write((bit<32>)hdr.detect.in_port, prt_srv);
            time_t cou1 = 0;  
            time_t cou2 = 0;  
            time_t cou3 = 0;  
            time_t cou4 = 0;  
            time_t cou5 = 0;  
            time_t cou6 = 0;  
            bit<8> portnum1; 
            bit<8> portnum2; 
            bit<8> portnum3; 
            bit<8> portnum4; 
            bit<8> portnum5; 
            bit<8> portnum6; 
            check_port.read(portnum1, 1); 
            check_port.read(portnum2, 2); 
            check_port.read(portnum3, 3); 
            check_port.read(portnum4, 4); 
            check_port.read(portnum5, 5); 
            check_port.read(portnum6, 6); 
            bit<5> res1; 
            bit<5> res2; 
            bit<5> res3; 
            bit<5> res4; 
            bit<5> res5; 
            bit<5> res6; 
            if (hdr.detect.in_port != 0) { 
                port_surv.read(cou1, 1);
                port_surv.read(cou2, 2);
                port_surv.read(cou3, 3);
                port_surv.read(cou4, 4);
                port_surv.read(cou5, 5);
                port_surv.read(cou6, 6);
                
	            port_count.read(res1, 1); 
	            port_count.read(res2, 2); 
	            port_count.read(res3, 3); 
	            port_count.read(res4, 4); 
	            port_count.read(res5, 5); 
	            port_count.read(res6, 6); 
	           	 
	            port_count.write((bit<32>)hdr.detect.in_port, 0x0);
                check_port.write((bit<32>)hdr.detect.in_port, 0);

                bit<8> tmp_port1; 
                failed_port.read(tmp_port1, 0);
                if (tmp_port1 == hdr.detect.in_port) {
                    failed_port.write(0, 0);
                    fail_occur.write((bit<32>)tmp_port1, 0);
                }
                failed_port.read(tmp_port1, 0);
                if (tmp_port1 != 0) {
                    time_t tmp_mytime;
                    fail_occur.read(tmp_mytime, (bit<32>)tmp_port1);
                    if (tmp_mytime != 0 && (time_t)standard_metadata.ingress_global_timestamp - tmp_mytime > CHECK_TIME) {
                        clone_flg_in.write(0, 0x0);
                        fail_occur.write((bit<32>)tmp_port1, (time_t)standard_metadata.ingress_global_timestamp);
                    }
                    else if (tmp_mytime == 0) fail_occur.write((bit<32>)tmp_port1, (time_t)standard_metadata.ingress_global_timestamp);
                }
                
                if (tmp_port1 == 0) {
                    if (prt_srv - cou1 > D*PRE_T && cou1 != 0 && res1 == 0) { 
                	    portnum1 = hdr.detect.in_port;	 
                    } 
                    if (prt_srv - cou2 > D*PRE_T && cou2 != 0 && res2 == 0) { 
                	    portnum2 = hdr.detect.in_port;	 
                    } 
                    if (prt_srv - cou3 > D*PRE_T && cou3 != 0 && res3 == 0) { 
                	    portnum3 = hdr.detect.in_port;	 
                    } 
                    if (prt_srv - cou4 > D*PRE_T && cou4 != 0 && res4 == 0) { 
                	    portnum4 = hdr.detect.in_port;	 
                    } 
                    if (prt_srv - cou5 > D*PRE_T && cou5 != 0 && res5 == 0) { 
                	    portnum5 = hdr.detect.in_port;	 
                    } 
                    if (prt_srv - cou6 > D*PRE_T && cou6 != 0 && res6 == 0) { 
                	    portnum6 = hdr.detect.in_port;	 
                    } 
                    if(portnum1 == hdr.detect.in_port){ 
                	    if (res1 >= C) {
                            failed_port.write(0, 1);
                        }
                        else {
                            check_port.write(1, hdr.detect.in_port);
                            clone_flg_in.write(0, 0x0);
                            res1 = res1 + 1;
                            port_count.write(1, res1);
                        }
                    }
                    if(portnum2 == hdr.detect.in_port){ 
                	    if (res2 >= C) {
                            failed_port.write(0, 2);
                        }
                        else {
                            check_port.write(2, hdr.detect.in_port);
                            clone_flg_in.write(0, 0x0);
                            res2 = res2 + 1;
                            port_count.write(2, res2);
                        }
                    }
                    if(portnum3 == hdr.detect.in_port){ 
                	    if (res3 >= C) {
                            failed_port.write(0, 3);
                        }
                        else {
                            check_port.write(3, hdr.detect.in_port);
                            clone_flg_in.write(0, 0x0);
                            res3 = res3 + 1;
                            port_count.write(3, res3);
                        }
                    }
                    if(portnum4 == hdr.detect.in_port){ 
                	    if (res4 >= C) {
                            failed_port.write(0, 4);
                        }
                        else {
                            check_port.write(4, hdr.detect.in_port);
                            clone_flg_in.write(0, 0x0);
                            res4 = res4 + 1;
                            port_count.write(4, res4);
                        }
                    }
                    if(portnum5 == hdr.detect.in_port){ 
                	    if (res5 >= C) {
                            failed_port.write(0, 5);
                        }
                        else {
                            check_port.write(5, hdr.detect.in_port);
                            clone_flg_in.write(0, 0x0);
                            res5 = res5 + 1;
                            port_count.write(5, res5);
                        }
                    }
                    if(portnum6 == hdr.detect.in_port){ 
                	    if (res6 >= C) {
                            failed_port.write(0, 6);
                        }
                        else {
                            check_port.write(6, hdr.detect.in_port);
                            clone_flg_in.write(0, 0x0);
                            res6 = res6 + 1;
                            port_count.write(6, res6);
                        }
                    }
                }
                
            }
        } 
        if (hdr.detect.isValid()) {
            if (hdr.detect.type == 0 && cln_flg == 0) {
                if (hdr.detect.in_time > D) {
                    cln_flg = 1;
                    clone_flg_in.write(0, cln_flg);
                    clone(CloneType.I2E, CLONE_SESSION);
                    bit<8> tmp_port1;
                    failed_port.read(tmp_port1, 0);
                    if (tmp_port1 != 0) {
                        if (standard_metadata.egress_port != (bit<9>)tmp_port1) {
                            drop();
                        }
                    }
                }
                else {
                    hdr.detect.d_flg = 1;
                }
            }
             
            else if (hdr.detect.type == 0 && cln_flg == 1) {
                if (hdr.detect.in_time > D) {
                    phy_return.apply();
                }
                else { 
                    hdr.detect.d_flg = 1;
                } 
            } 
        } 
         
        if (hdr.ipv4.isValid() && !hdr.bp.isValid()) { 
            ipv4_lpm.apply();
            bit<8> failed_port_tmp; 
            failed_port.read(failed_port_tmp, 0); 
            if (standard_metadata.egress_spec == (bit<9>)failed_port_tmp) {
                myheader_add();
                meta.my_metadata.failed_port = failed_port_tmp;
                adja_check.apply();
                bit<1> adja_ok_tmp; 
                adja_ok_check.read(adja_ok_tmp, 0); 
                if (adja_ok_tmp == 1) {
                    MRC_conf.apply(); 
                    adja_ok_check.write(0, 0x0); 
                } else {
                    MRC_Nodeconf_search.apply(); 
                }         
            } 
        } 
         
        if (hdr.bp.isValid()) { 
            confdst2port.apply();
            bit<8> failed_port_tmp; 
            failed_port.read(failed_port_tmp, 0);
            if (standard_metadata.egress_spec == (bit<9>)failed_port_tmp) { 
                drop(); 
            } 
            adja_check_host.apply();
            bit<1> adja_ok_tmp; 
            adja_ok_check.read(adja_ok_tmp, 0); 
            if (adja_ok_tmp == 1) {
                hdr.ethernet.etherType = hdr.bp.type; 
                hdr.bp.setInvalid(); 
                adja_ok_check.write(0, 0x0); 
            } 
        } 
    } 
 
} 
 
/************************************************************************* 
****************  E G R E S S   P R O C E S S I N G   ******************* 
*************************************************************************/ 
 
control MyEgress(inout headers hdr, 
                 inout metadata meta, 
    inout standard_metadata_t standard_metadata) { 
     
    action drop () { 
        mark_to_drop(standard_metadata); 
    } 
 
    action setAddr (macAddr_t srcAddr, macAddr_t dstAddr, bit<8> op_port) { 
        hdr.ethernet.srcAddr = srcAddr; 
        hdr.ethernet.dstAddr = dstAddr; 
        hdr.detect.in_port = op_port; 
    } 
    table look_port {
        key = { 
            standard_metadata.egress_port: exact; 
        } 
        actions = { 
            setAddr; 
            drop; 
        } 
        size = 1024; 
        default_action = drop(); 
    } 
     
    apply { 
        if (standard_metadata.egress_port == standard_metadata.ingress_port 
            && hdr.detect.type != 0) { 
            drop(); 
        } 
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl <= 0) { 
            drop(); 
        } 
        if (hdr.detect.isValid()) { 
            if (hdr.detect.type == 0) {
                if (hdr.detect.d_flg == 1) { 
                    hdr.detect.d_flg = 0; 
                    hdr.detect.r_flg = 1; 
                    hdr.detect.in_time = ((bit<32>)standard_metadata.egress_global_timestamp - (bit<32>)standard_metadata.ingress_global_timestamp); 
                    recirculate(standard_metadata); 
                } 
                else { 
                    hdr.detect.in_time         = 0; 
                    hdr.detect.r_flg = 0; 
                    if (hdr.detect.in_port != 0) { 
                        port_time.write((bit<32>)hdr.detect.in_port, standard_metadata.ingress_global_timestamp);
                    } 
                    look_port.apply();
                } 
            }
        }
    } 
} 
 
/************************************************************************* 
*************   C H E C K S U M    C O M P U T A T I O N   ************** 
*************************************************************************/ 
 
control MyComputeChecksum(inout headers hdr, inout metadata meta) { 
     apply { 
	update_checksum( 
	    hdr.ipv4.isValid(), 
            { hdr.ipv4.version, 
	          hdr.ipv4.ihl, 
              hdr.ipv4.tos, 
              hdr.ipv4.totalLen, 
              hdr.ipv4.identification, 
              hdr.ipv4.flags, 
              hdr.ipv4.fragOffset, 
              hdr.ipv4.ttl, 
              hdr.ipv4.protocol, 
              hdr.ipv4.srcAddr, 
              hdr.ipv4.dstAddr }, 
            hdr.ipv4.hdrChecksum, 
            HashAlgorithm.csum16); 
    } 
} 
 
 
/************************************************************************* 
***********************  D E P A R S E R  ******************************* 
*************************************************************************/ 
 
control MyDeparser(packet_out packet, in headers hdr) { 
    apply { 
        packet.emit(hdr.ethernet); 
        packet.emit(hdr.bp); 
        packet.emit(hdr.ipv4); 
        packet.emit(hdr.udp); 
        packet.emit(hdr.detect); 
    } 
} 
 
/************************************************************************* 
***********************  S W I T C H  ******************************* 
*************************************************************************/ 
 
V1Switch( 
MyParser(), 
MyVerifyChecksum(), 
MyIngress(), 
MyEgress(), 
MyComputeChecksum(), 
MyDeparser() 
) main; 
 
