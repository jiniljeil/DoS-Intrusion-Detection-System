# DoS-Intrusion Detection System

This IDS(Intrusion Detection System) detects denial of service attack.  

## Process

1. cicflowmeter execution
``` 
cicflowmeter -i [wifi-name] -c flows.csv
```
2. Packet sniffer captures the packets of the router. 

3. cicflowmeter extracts the features from packet information

4. The features on real-time is an input of model.  


## Structure

<img src="images/IDS.png" height=200px/>


## Report

https://github.com/jiniljeil/DoS-Intrusion-Detection-System/blob/master/IDS%20Final%20Report.pdf

## IDS Test

https://youtu.be/wBjDQ6sChoc

## References
1. https://github.com/datthinh1801/cicflowmeter   
2. https://www.unb.ca/cic/research/applications.html#CICFlowMeter   


