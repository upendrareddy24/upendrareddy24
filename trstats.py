import argparse
import subprocess as sp
import statistics
import pandas as pd
import json
import time
import os
import sys
import glob
parser = argparse.ArgumentParser(description='Run traceroute multiple times towards a given target host')
parser.add_argument('-n', dest='NUM_RUNS', type=int, default=1,
                    help='Number of times traceroute will run')
parser.add_argument('-d', dest='RUN_DELAY', default=1,
                    help='Number of seconds to wait between two consecutive runs')
parser.add_argument('-m', dest='MAX_HOPS', type=int, default=30,
                    help='Number of times traceroute will run')
parser.add_argument('-o', dest='OUTPUT', 
                    help='Path and name of output JSON file containing the stats ')
parser.add_argument('-g', dest='GRAPH',
                    help='Path and name of output PDF file containing stats graph')
parser.add_argument('-t', dest='TARGET',
                    help='A target domain name or IP address')
parser.add_argument('--test', dest='TEST_DIR',
                    help="""Directory containing num_runs text files, each of which
                   contains the output of a traceroute run.If present, this
                   will override all other options and tcpdump will not be
                   invoked. Stats will be computed over the traceroute output
                   stored in the text files""")

args = parser.parse_args()
no_of_runs = args.NUM_RUNS
run_delay = args.RUN_DELAY
max_hops = 0
if "MAX_HOPS" in args:
    max_hops = args.MAX_HOPS
if "OUTPUT" in args:
    output_path = args.OUTPUT
else:
    print("provide Output File Path")
    sys.exit(1)
if "GRAPH" in args:
    graph_path = args.GRAPH
else:
    print("provide Graph File Path")
    sys.exit(1)

if os.path.dirname(graph_path) and not os.path.isdir(os.path.dirname(graph_path)):
    os.makedirs(os.path.dirname(graph_path))
if os.path.dirname(output_path) and not os.path.isdir(os.path.dirname(output_path)):
    os.makedirs(os.path.dirname(output_path))
if "TARGET" in args:
    target = args.TARGET
elif "TEST_DIR" not in args:
    print("provide TARGET for tracerooute command or TEST_DIR")
    sys.exit(1)
test_dir = None
if "TEST_DIR" in args:
  test_dir = args.TEST_DIR
json_data = []
ip_full_list = [[]]
hop_time_list = [[]]
if max_hops:
    cmd= ["traceroute", target, "-m", str(max_hops)]
else:
    cmd=["traceroute", target]
def fetch_data(test_dir, no_of_runs):
    data_list = []
    if test_dir:
        list_files = glob.glob(os.path.join(test_dir, "*.out"))
        no_of_runs = len(list_files)
        for i in range(no_of_runs):
            with open(list_files[i], "r") as fd:
                data = fd.readlines()
            data_list.append(data)
    else:
        for k in range(no_of_runs):
            with sp.Popen(cmd, stdout=sp.PIPE, stderr=sp.PIPE) as proc:
                stdout = proc.communicate()[0]
                data=stdout.decode("utf-8").split("\n")
            data_list.append(data)
    return data_list, no_of_runs
data_list, no_of_runs = fetch_data(test_dir, no_of_runs)
for data in data_list:
    for i in range(1, len(data)):
        x= data[i].split()
        index_list = []
        ip_list = []
        for j in range(len(x)):
            if x[j] == 'ms':
                index_list.append(float(x[j-1]))
                if len(index_list) == 1:
                    ip_list.append((x[j-3], x[j-2]))
                elif x[j-2] not in ["ms", "*"]:
                    ip_list.append((x[j-3], x[j-2]))
        if ip_full_list and len(ip_full_list)-1 >= i:
            if ip_list:
                for l in ip_list:
                    if l not in ip_full_list[i]:
                        
                        ip_full_list[i].append(l)
            hop_time_list[i].extend(index_list)
        else:
            ip_full_list.append(ip_list)
            hop_time_list.append(index_list)
    time.sleep(run_delay)
no_of_hops = []
for i in range(1, len(hop_time_list)):
    
    if hop_time_list[i]:  
        min_x = min(hop_time_list[i])
        max_y = max(hop_time_list[i])
        mean = statistics.median(hop_time_list[i])
        avg = round(sum(hop_time_list[i])/len(hop_time_list[i]), 2)
    else:
        min_x = None
        max_y = None
        mean = None
        avg = None
    element = {'avg': avg, 'hop': i,
  'hosts': ip_full_list[i],
  'max': max_y,
  'med': mean,
  'min': min_x}
    json_data.append(element)
    no_of_hops.append("hop_"+str(i))
    

json_object = json.dumps(json_data, indent = 4)
  
# Writing to sample.json
with open(output_path, "w") as outfile:
    outfile.write(json_object)
    
import plotly.graph_objects as go
import plotly.io as iom

df=pd.DataFrame(columns=["hops", ""])

fig=go.Figure(layout=go.Layout())
for x, y in zip(no_of_hops, hop_time_list[1:]):
    fig.add_trace(go.Box(y=y, name=x, marker_size=2, jitter=0.5))
fig.update_xaxes(showgrid=True)
fig.update_yaxes(showgrid=True)
iom.write_image(fig, graph_path, format="pdf")
    



    

