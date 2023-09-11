import sys
from scapy.layers.inet import IP, TCP
from scapy.utils import rdpcap
from collections import defaultdict


def calculate_metrics(pcap_file):
    packets = rdpcap(pcap_file)

    rtts = defaultdict(list)
    throughput_data = defaultdict(int)
    flow_durations = defaultdict(lambda: [float('inf'), float('-inf')])

    sent_times = {}  # Dictionary to keep track of sequence numbers and their sent times

    for pkt in packets:
        if TCP in pkt and IP in pkt:
            src = (pkt[IP].src, pkt[TCP].sport)
            dst = (pkt[IP].dst, pkt[TCP].dport)
            flow = (src, dst)

            # Check for data packets and keep track of their sequence numbers and times
            if len(pkt[TCP].payload) > 0:
                seq = pkt[TCP].seq
                sent_times[seq] = pkt.time
                throughput_data[flow] += len(pkt[TCP].payload)

            # Check for ACKs corresponding to data packets and calculate RTTs
            elif pkt[TCP].ack in sent_times:
                rtt = pkt.time - sent_times[pkt[TCP].ack]
                rtts[flow].append(rtt)

            # Update the start and end times for the flow
            flow_durations[flow][0] = min(flow_durations[flow][0], pkt.time)
            flow_durations[flow][1] = max(flow_durations[flow][1], pkt.time)

    # Calculate average RTTs
    average_rtts = {flow: sum(times) / len(times)
                    for flow, times in rtts.items()}

    throughputs = {}
    for flow, data_bytes in throughput_data.items():
        start_time, end_time = flow_durations[flow]
        duration = end_time - start_time

        if duration == 0:
            throughputs[flow] = 0.0
        else:
            throughputs[flow] = (float(data_bytes) * 8.0 /
                                 (10**6)) / float(duration)

    return average_rtts, throughputs


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python pcap_tcp_metrics_analyzer.py <path_to_pcap_file>")
        sys.exit(1)

    pcap_file_path = sys.argv[1]
    average_rtt_values, throughput_values = calculate_metrics(pcap_file_path)

    for (src, dst) in average_rtt_values.keys():
        avg_rtt = average_rtt_values[(src, dst)] * 1000
        throughput = throughput_values[(src, dst)]
        print(
            f"Flow from {src[0]}:{src[1]} to {dst[0]}:{dst[1]} - Average RTT: {avg_rtt:.2f} ms, Throughput: {throughput:.2f} Mbps")
