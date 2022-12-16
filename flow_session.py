import csv
from collections import defaultdict

from scapy.sessions import DefaultSession

from .features.context.packet_direction import PacketDirection
from .features.context.packet_flow_key import get_packet_flow_key
from .flow import Flow
import tensorflow as tf
import numpy as np 
from keras.models import load_model
from sklearn.preprocessing import LabelEncoder, normalize

import logging

attack_categories = ["Benign", "DoS Attacks"] 
# attack_categories = [ "Benign", "DoS attacks-SlowHTTPTest","DoS attacks-Hulk"]  
#attack_categories = ["Benign", "Brute Force -Web", "Brute Force -XSS", "SQL Injection"] 

EXPIRED_UPDATE = 40
MACHINE_LEARNING_API = "http://localhost:8000/predict"
GARBAGE_COLLECT_PACKETS = 100
# localhost_save_option = tf.saved_model.SaveOptions(experimental_io_device="/job:localhost")

# model = load_model('hello.h5')
model = load_model('IDS_model.h5')

logger = logging.getLogger('simple_example')
logger.setLevel(logging.DEBUG)

# 콘솔 출력을 지정합니다
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

# 파일 출력을 지정합니다.
fh = logging.FileHandler(filename="run.log")
fh.setLevel(logging.INFO)

# add ch to logger
logger.addHandler(ch)
logger.addHandler(fh)

def softmax(a):
    c = np.max(a)   
    exp_a = np.exp(a - c)       # 오버플로우를 막기 위해서
    sum_exp_a = np.sum(exp_a)
    y = exp_a / sum_exp_a

    return y
    
class FlowSession(DefaultSession):
    """Creates a list of network flows."""

    def __init__(self, *args, **kwargs):
        self.flows = {}
        self.csv_line = 0
        
        if self.output_mode == "flow":
            output = open(self.output_file, "w")
            self.csv_writer = csv.writer(output)

        self.packets_count = 0

        self.clumped_flows_per_label = defaultdict(list)

        super(FlowSession, self).__init__(*args, **kwargs)

    def toPacketList(self):
        # Sniffer finished all the packets it needed to sniff.
        # It is not a good place for this, we need to somehow define a finish signal for AsyncSniffer
        self.garbage_collect(None)
        return super(FlowSession, self).toPacketList()

    def on_packet_received(self, packet):
        count = 0
        direction = PacketDirection.FORWARD

        if self.output_mode != "flow":
            if "TCP" not in packet:
                return
            elif "UDP" not in packet:
                return

        try:
            # Creates a key variable to check
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))
        except Exception:
            return

        self.packets_count += 1

        # If there is no forward flow with a count of 0
        if flow is None:
            # There might be one of it in reverse
            direction = PacketDirection.REVERSE
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))

        if flow is None:
            # If no flow exists create a new flow
            direction = PacketDirection.FORWARD
            flow = Flow(packet, direction)
            packet_flow_key = get_packet_flow_key(packet, direction)
            self.flows[(packet_flow_key, count)] = flow

        elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
            # If the packet exists in the flow but the packet is sent
            # after too much of a delay than it is a part of a new flow.
            expired = EXPIRED_UPDATE
            while (packet.time - flow.latest_timestamp) > expired:
                count += 1
                expired += EXPIRED_UPDATE
                flow = self.flows.get((packet_flow_key, count))

                if flow is None:
                    flow = Flow(packet, direction)
                    self.flows[(packet_flow_key, count)] = flow
                    break
        elif "F" in str(packet.flags):
            # If it has FIN flag then early collect flow and continue
            flow.add_packet(packet, direction)
            self.garbage_collect(packet.time)
            return

        flow.add_packet(packet, direction)

        if not self.url_model:
            GARBAGE_COLLECT_PACKETS = 10000

        if self.packets_count % GARBAGE_COLLECT_PACKETS == 0 or (
            flow.duration > 120 and self.output_mode == "flow"
        ):
            self.garbage_collect(packet.time)

    def get_flows(self) -> list:
        return self.flows.values()

    def garbage_collect(self, latest_time) -> None:
        # TODO: Garbage Collection / Feature Extraction should have a separate thread
        """
        if not self.url_model:
            print("Garbage Collection Began. Flows = {}".format(len(self.flows)))
        """
        keys = list(self.flows.keys())
        for k in keys:
            flow = self.flows.get(k)
            
        
            if (
                latest_time is None
                or latest_time - flow.latest_timestamp > EXPIRED_UPDATE
                or flow.duration > 90
            ):
            
                data = flow.get_data()

                if self.csv_line == 0:
                    self.csv_writer.writerow(data.keys())

                self.csv_writer.writerow(data.values())
                self.csv_line += 1
                
                data_copy = data.copy() 

                if 'timestamp' in data_copy: 
                    del data_copy['src_ip']
                    del data_copy['dst_ip']
                    del data_copy['src_port']
                    del data_copy['timestamp']

                X = normalize(np.array([list(data_copy.values())]))
                result = model.predict(X)
                res = softmax(result)
                
                # print("RES TYPE: ", type(res)) 
                """
                index_v = 0 
                index_d = 0 
                for i in range(len(res)): 
                    if index_v < res[i]:
                        index_v = res[i]
                        index_d = i 
                """ 
                # print("RESULT: ", result) 
                # print("RESL ", res) 
                
                logger.info(f"Attack category: {attack_categories[np.argmax(res)]}" )
                    # print("Category: ",res.index(max(res)))

                del self.flows[k]
        """
        if not self.url_model:
            print("Garbage Collection Finished. Flows = {}".format(len(self.flows)))
        """
    
def generate_session_class(output_mode, output_file, url_model):
    return type(
        "NewFlowSession",
        (FlowSession,),
        {
            "output_mode": output_mode,
            "output_file": output_file,
            "url_model": url_model,
        },
    )
