## Control free IP address (L-IPAM managed IP warm pool) for EKS cluster
### 1. Prepare knowledge
#### 1.1) IP addresses per network interface per instance type
[https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html)

command for getting Max number of ENI(s) and IP addresses per ENI   
```
aws ec2 describe-instance-types --filters "Name=instance-type,Values=m5.*" --query "InstanceTypes[].{Type: InstanceType, MaxENI: NetworkInfo.MaximumNetworkInterfaces, IPv4addr: NetworkInfo.Ipv4AddressesPerInterface}" --output table
```
Example for EC2 M5 type:   
```
[ec2-user@ip-172-31-1-111 ekslab]$ aws ec2 describe-instance-types --filters "Name=instance-type,Values=m5.*" --query "InstanceTypes[].{Type: InstanceType, MaxENI: NetworkInfo.MaximumNetworkInterfaces, IPv4addr: NetworkInfo.Ipv4AddressesPerInterface}" --output table
---------------------------------------
|        DescribeInstanceTypes        |
+----------+----------+---------------+
| IPv4addr | MaxENI   |     Type      |
+----------+----------+---------------+
|  30      |  8       |  m5.4xlarge   |
|  30      |  8       |  m5.8xlarge   |
|  50      |  15      |  m5.24xlarge  |
|  50      |  15      |  m5.metal     |
|  30      |  8       |  m5.12xlarge  |
|  15      |  4       |  m5.xlarge    |
|  50      |  15      |  m5.16xlarge  |
|  10      |  3       |  m5.large     |
|  15      |  4       |  m5.2xlarge   |
+----------+----------+---------------+
```

#### 1.2) Pod networking (CNI) for AWS EKS   
Official document:  
[https://docs.aws.amazon.com/eks/latest/userguide/pod-networking.html](https://docs.aws.amazon.com/eks/latest/userguide/pod-networking.html)
```txt  
When you create an Amazon EKS node, it has one network interface. All Amazon EC2 instance types support more than one network interface. The network interface attached to the instance when the instance is created is called the primary network interface. Any additional network interface attached to the instance is called a secondary network interface. Each network interface can be assigned multiple private IP addresses. One of the private IP addresses is the primary IP address, whereas all other addresses assigned to the network interface are secondary IP addresses.    
The Amazon VPC Container Network Interface (CNI) plugin for Kubernetes is deployed with each of your Amazon EC2 nodes in a Daemonset with the name aws-node. The plugin consists of two primary components: CNI plugin and L-IPAM daemon.    
The default is a WARM_ENI_TARGET=1 setting. This means that EKS will attempt to keep one entire ENI spare on the node. So if a node has an ENI attached and any of those IPs are used, then it will attach another ENI so this default setting is observed.
```

### 2. Create EKS cluster (optional) 
You can follow following link to create EKS cluster:  
[https://github.com/jerryjin2018/AWS-China-EKS-Workshop-2021/blob/main/Lab1:%20Create%20an%20EKS%20cluster%20through%20eksctl%20(version%201.21%20%40%202021.11.25).md](https://github.com/jerryjin2018/AWS-China-EKS-Workshop-2021/blob/main/Lab1:%20Create%20an%20EKS%20cluster%20through%20eksctl%20(version%201.21%20%40%202021.11.25).md)


### 3. Get basic information regarding EKS cluster
**please make sure aws cli has been installed correctly.**
#### 3.1) How many ENI(s) have been used for worker nodes(EC2 instances) in EKS cluster
```
INSTANCE="i-0972868e0206d66d7 i-0d6e6ff8f456f8989 i-0e93c08b4dda4be18"
for INS in ${INSTANCE}
do
    echo "EC2 -- ${INS} is/are with ENI(s):"
    aws ec2 describe-instances --instance-ids ${INS} | jq .Reservations[0].Instances[0].NetworkInterfaces[].NetworkInterfaceId
    echo -e ""
done
```
Example for how many ENI(s) used for EC2 instance:   
```
[ec2-user@ip-172-31-1-111 ~]$ INSTANCE="i-0972868e0206d66d7 i-0d6e6ff8f456f8989 i-0e93c08b4dda4be18"
[ec2-user@ip-172-31-1-111 ~]$ for INS in ${INSTANCE}
> do
>     echo "EC2 -- ${INS} is/are with ENI(s):"
>     aws ec2 describe-instances --instance-ids ${INS} | jq .Reservations[0].Instances[0].NetworkInterfaces[].NetworkInterfaceId
>     echo -e ""
> done
EC2 -- i-0972868e0206d66d7 is/are with ENI(s):
"eni-0ff62bede9ad580a0"

EC2 -- i-0d6e6ff8f456f8989 is/are with ENI(s):
"eni-09a6dce1c9dba60ba"
"eni-03cca927034df4220"

EC2 -- i-0e93c08b4dda4be18 is/are with ENI(s):
"eni-0c595eb3274d13e26"
"eni-0cb12e30d7a355c2b"
```

#### 3.2) How many IP(s) were assigned fore each worker node 
```
INSTANCE="i-0972868e0206d66d7 i-0d6e6ff8f456f8989 i-0e93c08b4dda4be18"
for INS in ${INSTANCE}
do
    echo "EC2 -- ${INS} is assigned IP(s):"
    aws ec2 describe-instances --instance-ids ${INS} | jq .Reservations[0].Instances[0].NetworkInterfaces[].PrivateIpAddresses | grep PrivateIpAddress | wc -l
    aws ec2 describe-instances --instance-ids ${INS} | jq .Reservations[0].Instances[0].NetworkInterfaces[].PrivateIpAddresses | grep PrivateIpAddress
    echo -e ""
done
```
Example for how many IP(s) used for each ENI(s):   
```
[ec2-user@ip-172-31-1-111 ~]$ INSTANCE="i-0972868e0206d66d7 i-0d6e6ff8f456f8989 i-0e93c08b4dda4be18"
[ec2-user@ip-172-31-1-111 ~]$ for INS in ${INSTANCE}
> do
>     echo "EC2 -- ${INS} is assigned IP(s):"
>     aws ec2 describe-instances --instance-ids ${INS} | jq .Reservations[0].Instances[0].NetworkInterfaces[].PrivateIpAddresses | grep PrivateIpAddress | wc -l
>     aws ec2 describe-instances --instance-ids ${INS} | jq .Reservations[0].Instances[0].NetworkInterfaces[].PrivateIpAddresses | grep PrivateIpAddress
>     echo -e ""
> done
EC2 -- i-0972868e0206d66d7 is assigned IP(s):
10
    "PrivateIpAddress": "192.168.63.35"
    "PrivateIpAddress": "192.168.37.122"
    "PrivateIpAddress": "192.168.60.28"
    "PrivateIpAddress": "192.168.51.109"
    "PrivateIpAddress": "192.168.47.61"
    "PrivateIpAddress": "192.168.56.174"
    "PrivateIpAddress": "192.168.55.81"
    "PrivateIpAddress": "192.168.33.117"
    "PrivateIpAddress": "192.168.62.230"
    "PrivateIpAddress": "192.168.58.198"

EC2 -- i-0d6e6ff8f456f8989 is assigned IP(s):
20
    "PrivateIpAddress": "192.168.85.184"
    "PrivateIpAddress": "192.168.72.72"
    "PrivateIpAddress": "192.168.90.153"
    "PrivateIpAddress": "192.168.77.169"
    "PrivateIpAddress": "192.168.64.90"
    "PrivateIpAddress": "192.168.65.218"
    "PrivateIpAddress": "192.168.93.212"
    "PrivateIpAddress": "192.168.81.21"
    "PrivateIpAddress": "192.168.79.214"
    "PrivateIpAddress": "192.168.64.86"
    "PrivateIpAddress": "192.168.65.9"
    "PrivateIpAddress": "192.168.75.248"
    "PrivateIpAddress": "192.168.75.204"
    "PrivateIpAddress": "192.168.86.205"
    "PrivateIpAddress": "192.168.78.221"
    "PrivateIpAddress": "192.168.72.128"
    "PrivateIpAddress": "192.168.65.82"
    "PrivateIpAddress": "192.168.75.118"
    "PrivateIpAddress": "192.168.83.38"
    "PrivateIpAddress": "192.168.91.39"

EC2 -- i-0e93c08b4dda4be18 is assigned IP(s):
20
    "PrivateIpAddress": "192.168.5.84"
    "PrivateIpAddress": "192.168.28.74"
    "PrivateIpAddress": "192.168.0.220"
    "PrivateIpAddress": "192.168.2.144"
    "PrivateIpAddress": "192.168.17.129"
    "PrivateIpAddress": "192.168.27.49"
    "PrivateIpAddress": "192.168.6.98"
    "PrivateIpAddress": "192.168.1.195"
    "PrivateIpAddress": "192.168.16.22"
    "PrivateIpAddress": "192.168.9.150"
    "PrivateIpAddress": "192.168.10.223"
    "PrivateIpAddress": "192.168.1.120"
    "PrivateIpAddress": "192.168.19.172"
    "PrivateIpAddress": "192.168.27.108"
    "PrivateIpAddress": "192.168.4.13"
    "PrivateIpAddress": "192.168.23.65"
    "PrivateIpAddress": "192.168.24.145"
    "PrivateIpAddress": "192.168.13.130"
    "PrivateIpAddress": "192.168.21.99"
    "PrivateIpAddress": "192.168.0.37"
```

#### 3.3) Relationship between Nodes and Pods
```
[ec2-user@ip-172-31-1-111 ~]$ kubectl get nodes
NAME                                                STATUS   ROLES    AGE   VERSION
ip-192-168-5-84.cn-northwest-1.compute.internal     Ready    <none>   23h   v1.18.20-eks-c9f1ce
ip-192-168-63-35.cn-northwest-1.compute.internal    Ready    <none>   23h   v1.18.20-eks-c9f1ce
ip-192-168-85-184.cn-northwest-1.compute.internal   Ready    <none>   23h   v1.18.20-eks-c9f1ce

[ec2-user@ip-172-31-1-111 ~]$ kubectl get pod -o=custom-columns=NAME:.metadata.name,STATUS:.status.phase,NODE:.spec.nodeName --all-namespaces | sort -k 3
NAME                       STATUS    NODE
aws-node-kr9lr             Running   ip-192-168-5-84.cn-northwest-1.compute.internal
coredns-58d46ddb7f-l5f9m   Running   ip-192-168-5-84.cn-northwest-1.compute.internal
kube-proxy-p542n           Running   ip-192-168-5-84.cn-northwest-1.compute.internal
aws-node-dnk4k             Running   ip-192-168-63-35.cn-northwest-1.compute.internal
kube-proxy-d5cvg           Running   ip-192-168-63-35.cn-northwest-1.compute.internal
aws-node-xg9wl             Running   ip-192-168-85-184.cn-northwest-1.compute.internal
coredns-58d46ddb7f-2rvrh   Running   ip-192-168-85-184.cn-northwest-1.compute.internal
kube-proxy-w2t7j           Running   ip-192-168-85-184.cn-northwest-1.compute.internal
```

### 4. Create a test application   
Create a deployment and service    
```
---
apiVersion: v1
kind: Namespace
metadata:
  name: net-test
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  namespace: net-test
  labels:
    app: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx-net
  template:
    metadata:
      labels:
        app: nginx-net
    spec:
      containers:
      - name: nginx
        image: nginx
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: nginx-service-clusterip
  namespace: net-test
spec:
  type: ClusterIP
  selector:
    app: nginx-net
  ports:
    - protocol: TCP
      port: 8080
      targetPort: 80
``` 


### 5. Get information regarding EKS cluster again
#### 5.1) Relationship between Nodes and Pods again
```
[ec2-user@ip-172-31-1-111 ekslab]$ kubectl get pod -o=custom-columns=NAME:.metadata.name,STATUS:.status.phase,NODE:.spec.nodeName --all-namespaces | sort -k 3
NAME                                STATUS    NODE
aws-node-kr9lr                      Running   ip-192-168-5-84.cn-northwest-1.compute.internal
coredns-58d46ddb7f-l5f9m            Running   ip-192-168-5-84.cn-northwest-1.compute.internal
kube-proxy-p542n                    Running   ip-192-168-5-84.cn-northwest-1.compute.internal
nginx-deployment-5c4b788944-lm8fn   Running   ip-192-168-5-84.cn-northwest-1.compute.internal
aws-node-dnk4k                      Running   ip-192-168-63-35.cn-northwest-1.compute.internal
kube-proxy-d5cvg                    Running   ip-192-168-63-35.cn-northwest-1.compute.internal
nginx-deployment-5c4b788944-9rgjc   Running   ip-192-168-63-35.cn-northwest-1.compute.internal
aws-node-xg9wl                      Running   ip-192-168-85-184.cn-northwest-1.compute.internal
coredns-58d46ddb7f-2rvrh            Running   ip-192-168-85-184.cn-northwest-1.compute.internal
kube-proxy-w2t7j                    Running   ip-192-168-85-184.cn-northwest-1.compute.internal
nginx-deployment-5c4b788944-7wrtd   Running   ip-192-168-85-184.cn-northwest-1.compute.internal
```

#### 5.2) Check again, how many ENI(s) have been used for worker nodes(EC2 instances) in EKS cluster
  
```
INSTANCE="i-0972868e0206d66d7 i-0d6e6ff8f456f8989 i-0e93c08b4dda4be18"
for INS in ${INSTANCE}
do
    echo "EC2 -- ${INS} is/are with ENI(s):"
    aws ec2 describe-instances --instance-ids ${INS} | jq .Reservations[0].Instances[0].NetworkInterfaces[].NetworkInterfaceId
    echo -e ""
done
```

```
[ec2-user@ip-172-31-1-111 ekslab]$ INSTANCE="i-0972868e0206d66d7 i-0d6e6ff8f456f8989 i-0e93c08b4dda4be18"
[ec2-user@ip-172-31-1-111 ekslab]$ for INS in ${INSTANCE}
> do
>     echo "EC2 -- ${INS} is/are with ENI(s):"
>     aws ec2 describe-instances --instance-ids ${INS} | jq .Reservations[0].Instances[0].NetworkInterfaces[].NetworkInterfaceId
>     echo -e ""
> done
EC2 -- i-0972868e0206d66d7 is/are with ENI(s):
"eni-0ff62bede9ad580a0"
"eni-064cb1574849630d6"

EC2 -- i-0d6e6ff8f456f8989 is/are with ENI(s):
"eni-09a6dce1c9dba60ba"
"eni-03cca927034df4220"

EC2 -- i-0e93c08b4dda4be18 is/are with ENI(s):
"eni-0c595eb3274d13e26"
"eni-0cb12e30d7a355c2b"
```

#### 5.3) Check again, How many IP(s) were assigned fore each worker node   
  
```
INSTANCE="i-0972868e0206d66d7 i-0d6e6ff8f456f8989 i-0e93c08b4dda4be18"
for INS in ${INSTANCE}
do
    echo "EC2 -- ${INS} is assigned IP(s):"
    aws ec2 describe-instances --instance-ids ${INS} | jq .Reservations[0].Instances[0].NetworkInterfaces[].PrivateIpAddresses | grep PrivateIpAddress | wc -l
    aws ec2 describe-instances --instance-ids ${INS} | jq .Reservations[0].Instances[0].NetworkInterfaces[].PrivateIpAddresses | grep PrivateIpAddress
    echo -e ""
done
```
```
[ec2-user@ip-172-31-1-111 ekslab]$ INSTANCE="i-0972868e0206d66d7 i-0d6e6ff8f456f8989 i-0e93c08b4dda4be18"
[ec2-user@ip-172-31-1-111 ekslab]$ for INS in ${INSTANCE}
> do
>     echo "EC2 -- ${INS} is assigned IP(s):"
>     aws ec2 describe-instances --instance-ids ${INS} | jq .Reservations[0].Instances[0].NetworkInterfaces[].PrivateIpAddresses | grep PrivateIpAddress | wc -l
>     aws ec2 describe-instances --instance-ids ${INS} | jq .Reservations[0].Instances[0].NetworkInterfaces[].PrivateIpAddresses | grep PrivateIpAddress
>     echo -e ""
> done
EC2 -- i-0972868e0206d66d7 is assigned IP(s):
20
    "PrivateIpAddress": "192.168.63.35"
    "PrivateIpAddress": "192.168.37.122"
    "PrivateIpAddress": "192.168.60.28"
    "PrivateIpAddress": "192.168.51.109"
    "PrivateIpAddress": "192.168.47.61"
    "PrivateIpAddress": "192.168.56.174"
    "PrivateIpAddress": "192.168.55.81"
    "PrivateIpAddress": "192.168.33.117"
    "PrivateIpAddress": "192.168.62.230"
    "PrivateIpAddress": "192.168.58.198"
    "PrivateIpAddress": "192.168.57.119"
    "PrivateIpAddress": "192.168.56.216"
    "PrivateIpAddress": "192.168.52.169"
    "PrivateIpAddress": "192.168.47.137"
    "PrivateIpAddress": "192.168.56.242"
    "PrivateIpAddress": "192.168.60.162"
    "PrivateIpAddress": "192.168.34.51"
    "PrivateIpAddress": "192.168.56.132"
    "PrivateIpAddress": "192.168.32.36"
    "PrivateIpAddress": "192.168.59.21"

EC2 -- i-0d6e6ff8f456f8989 is assigned IP(s):
20
    "PrivateIpAddress": "192.168.85.184"
    "PrivateIpAddress": "192.168.72.72"
    "PrivateIpAddress": "192.168.90.153"
    "PrivateIpAddress": "192.168.77.169"
    "PrivateIpAddress": "192.168.64.90"
    "PrivateIpAddress": "192.168.65.218"
    "PrivateIpAddress": "192.168.93.212"
    "PrivateIpAddress": "192.168.81.21"
    "PrivateIpAddress": "192.168.79.214"
    "PrivateIpAddress": "192.168.64.86"
    "PrivateIpAddress": "192.168.65.9"
    "PrivateIpAddress": "192.168.75.248"
    "PrivateIpAddress": "192.168.75.204"
    "PrivateIpAddress": "192.168.86.205"
    "PrivateIpAddress": "192.168.78.221"
    "PrivateIpAddress": "192.168.72.128"
    "PrivateIpAddress": "192.168.65.82"
    "PrivateIpAddress": "192.168.75.118"
    "PrivateIpAddress": "192.168.83.38"
    "PrivateIpAddress": "192.168.91.39"

EC2 -- i-0e93c08b4dda4be18 is assigned IP(s):
20
    "PrivateIpAddress": "192.168.5.84"
    "PrivateIpAddress": "192.168.28.74"
    "PrivateIpAddress": "192.168.0.220"
    "PrivateIpAddress": "192.168.2.144"
    "PrivateIpAddress": "192.168.17.129"
    "PrivateIpAddress": "192.168.27.49"
    "PrivateIpAddress": "192.168.6.98"
    "PrivateIpAddress": "192.168.1.195"
    "PrivateIpAddress": "192.168.16.22"
    "PrivateIpAddress": "192.168.9.150"
    "PrivateIpAddress": "192.168.10.223"
    "PrivateIpAddress": "192.168.1.120"
    "PrivateIpAddress": "192.168.19.172"
    "PrivateIpAddress": "192.168.27.108"
    "PrivateIpAddress": "192.168.4.13"
    "PrivateIpAddress": "192.168.23.65"
    "PrivateIpAddress": "192.168.24.145"
    "PrivateIpAddress": "192.168.13.130"
    "PrivateIpAddress": "192.168.21.99"
    "PrivateIpAddress": "192.168.0.37"
```

#### 5.4) Check value of WARM_ENI_TARGET for aws-node pod  
```
PNAME=$(kubectl get pod -n kube-system | grep -i aws-node | awk '{print $1}')
for PP in ${PNAME}
do
    echo "Pod name -- ${PP}:"
    kubectl describe pod ${PP} -n kube-system | grep -iE "WARM|MINIMUM"
    echo -e ""
done
```

```
[ec2-user@ip-172-31-1-111 ekslab]$ PNAME=$(kubectl get pod -n kube-system | grep -i aws-node | awk '{print $1}')
[ec2-user@ip-172-31-1-111 ekslab]$ for PP in ${PNAME}
> do
>     echo "Pod name -- ${PP}:"
>     kubectl describe pod ${PP} -n kube-system | grep -iE "WARM|MINIMUM"
>     echo -e ""
> done
Pod name -- aws-node-dnk4k:
      WARM_ENI_TARGET:                     1

Pod name -- aws-node-kr9lr:
      WARM_ENI_TARGET:                     1

Pod name -- aws-node-xg9wl:
      WARM_ENI_TARGET:                     1
```

#### 5.5) Scale up the number of Pod to 30   
```
[ec2-user@ip-172-31-1-111 ekslab]$ kubectl scale deployments.apps/nginx-deployment --replicas=30 -n net-test 
deployment.apps/nginx-deployment scaled
   
[ec2-user@ip-172-31-1-111 ekslab]$ kubectl get deployments.apps -n net-test
NAME               READY   UP-TO-DATE   AVAILABLE   AGE
nginx-deployment   30/30   30           30          48m
```

### 6. Get information regarding EKS cluster again too
#### 6.1) Check again, how many ENI(s) have been used for worker nodes(EC2 instances) in EKS cluster
```
INSTANCE="i-0972868e0206d66d7 i-0d6e6ff8f456f8989 i-0e93c08b4dda4be18"
for INS in ${INSTANCE}
do
    echo "EC2 -- ${INS} is/are with ENI(s):"
    aws ec2 describe-instances --instance-ids ${INS} | jq .Reservations[0].Instances[0].NetworkInterfaces[].NetworkInterfaceId
    echo -e ""
done
```

```
[ec2-user@ip-172-31-1-111 ekslab]$ INSTANCE="i-0972868e0206d66d7 i-0d6e6ff8f456f8989 i-0e93c08b4dda4be18"
[ec2-user@ip-172-31-1-111 ekslab]$ for INS in ${INSTANCE}
> do
>     echo "EC2 -- ${INS} is/are with ENI(s):"
>     aws ec2 describe-instances --instance-ids ${INS} | jq .Reservations[0].Instances[0].NetworkInterfaces[].NetworkInterfaceId
>     echo -e ""
> done
EC2 -- i-0972868e0206d66d7 is/are with ENI(s):
"eni-0ff62bede9ad580a0"
"eni-064cb1574849630d6"
"eni-0f765de10ba33c7f6"

EC2 -- i-0d6e6ff8f456f8989 is/are with ENI(s):
"eni-09a6dce1c9dba60ba"
"eni-03cca927034df4220"
"eni-0be520e4263315185"

EC2 -- i-0e93c08b4dda4be18 is/are with ENI(s):
"eni-0c595eb3274d13e26"
"eni-0cb12e30d7a355c2b"
"eni-0532a95e3400e5073"
```

#### 6.2) Check again, How many IP(s) were assigned fore each worker node 
```
INSTANCE="i-0972868e0206d66d7 i-0d6e6ff8f456f8989 i-0e93c08b4dda4be18"
for INS in ${INSTANCE}
do
    echo "EC2 -- ${INS} is assigned IP(s):"
    aws ec2 describe-instances --instance-ids ${INS} | jq .Reservations[0].Instances[0].NetworkInterfaces[].PrivateIpAddresses | grep PrivateIpAddress | wc -l
    aws ec2 describe-instances --instance-ids ${INS} | jq .Reservations[0].Instances[0].NetworkInterfaces[].PrivateIpAddresses | grep PrivateIpAddress
    echo -e ""
done
```

```
[ec2-user@ip-172-31-1-111 ekslab]$ INSTANCE="i-0972868e0206d66d7 i-0d6e6ff8f456f8989 i-0e93c08b4dda4be18"
[ec2-user@ip-172-31-1-111 ekslab]$ for INS in ${INSTANCE}
> do
>     echo "EC2 -- ${INS} is assigned IP(s):"
>     aws ec2 describe-instances --instance-ids ${INS} | jq .Reservations[0].Instances[0].NetworkInterfaces[].PrivateIpAddresses | grep PrivateIpAddress | wc -l
>     aws ec2 describe-instances --instance-ids ${INS} | jq .Reservations[0].Instances[0].NetworkInterfaces[].PrivateIpAddresses | grep PrivateIpAddress
>     echo -e ""
> done
EC2 -- i-0972868e0206d66d7 is assigned IP(s):
30
    "PrivateIpAddress": "192.168.63.35"
    "PrivateIpAddress": "192.168.37.122"
    "PrivateIpAddress": "192.168.60.28"
    "PrivateIpAddress": "192.168.51.109"
    "PrivateIpAddress": "192.168.47.61"
    "PrivateIpAddress": "192.168.56.174"
    "PrivateIpAddress": "192.168.55.81"
    "PrivateIpAddress": "192.168.33.117"
    "PrivateIpAddress": "192.168.62.230"
    "PrivateIpAddress": "192.168.58.198"
    "PrivateIpAddress": "192.168.57.119"
    "PrivateIpAddress": "192.168.56.216"
    "PrivateIpAddress": "192.168.52.169"
    "PrivateIpAddress": "192.168.47.137"
    "PrivateIpAddress": "192.168.56.242"
    "PrivateIpAddress": "192.168.60.162"
    "PrivateIpAddress": "192.168.34.51"
    "PrivateIpAddress": "192.168.56.132"
    "PrivateIpAddress": "192.168.32.36"
    "PrivateIpAddress": "192.168.59.21"
    "PrivateIpAddress": "192.168.62.179"
    "PrivateIpAddress": "192.168.33.106"
    "PrivateIpAddress": "192.168.55.108"
    "PrivateIpAddress": "192.168.48.13"
    "PrivateIpAddress": "192.168.61.126"
    "PrivateIpAddress": "192.168.43.174"
    "PrivateIpAddress": "192.168.46.30"
    "PrivateIpAddress": "192.168.45.129"
    "PrivateIpAddress": "192.168.43.19"
    "PrivateIpAddress": "192.168.51.179"

EC2 -- i-0d6e6ff8f456f8989 is assigned IP(s):
30
    "PrivateIpAddress": "192.168.85.184"
    "PrivateIpAddress": "192.168.72.72"
    "PrivateIpAddress": "192.168.90.153"
    "PrivateIpAddress": "192.168.77.169"
    "PrivateIpAddress": "192.168.64.90"
    "PrivateIpAddress": "192.168.65.218"
    "PrivateIpAddress": "192.168.93.212"
    "PrivateIpAddress": "192.168.81.21"
    "PrivateIpAddress": "192.168.79.214"
    "PrivateIpAddress": "192.168.64.86"
    "PrivateIpAddress": "192.168.65.9"
    "PrivateIpAddress": "192.168.75.248"
    "PrivateIpAddress": "192.168.75.204"
    "PrivateIpAddress": "192.168.86.205"
    "PrivateIpAddress": "192.168.78.221"
    "PrivateIpAddress": "192.168.72.128"
    "PrivateIpAddress": "192.168.65.82"
    "PrivateIpAddress": "192.168.75.118"
    "PrivateIpAddress": "192.168.83.38"
    "PrivateIpAddress": "192.168.91.39"
    "PrivateIpAddress": "192.168.75.249"
    "PrivateIpAddress": "192.168.83.42"
    "PrivateIpAddress": "192.168.89.107"
    "PrivateIpAddress": "192.168.68.221"
    "PrivateIpAddress": "192.168.64.126"
    "PrivateIpAddress": "192.168.92.162"
    "PrivateIpAddress": "192.168.91.2"
    "PrivateIpAddress": "192.168.89.164"
    "PrivateIpAddress": "192.168.78.36"
    "PrivateIpAddress": "192.168.72.118"

EC2 -- i-0e93c08b4dda4be18 is assigned IP(s):
30
    "PrivateIpAddress": "192.168.5.84"
    "PrivateIpAddress": "192.168.28.74"
    "PrivateIpAddress": "192.168.0.220"
    "PrivateIpAddress": "192.168.2.144"
    "PrivateIpAddress": "192.168.17.129"
    "PrivateIpAddress": "192.168.27.49"
    "PrivateIpAddress": "192.168.6.98"
    "PrivateIpAddress": "192.168.1.195"
    "PrivateIpAddress": "192.168.16.22"
    "PrivateIpAddress": "192.168.9.150"
    "PrivateIpAddress": "192.168.10.223"
    "PrivateIpAddress": "192.168.1.120"
    "PrivateIpAddress": "192.168.19.172"
    "PrivateIpAddress": "192.168.27.108"
    "PrivateIpAddress": "192.168.4.13"
    "PrivateIpAddress": "192.168.23.65"
    "PrivateIpAddress": "192.168.24.145"
    "PrivateIpAddress": "192.168.13.130"
    "PrivateIpAddress": "192.168.21.99"
    "PrivateIpAddress": "192.168.0.37"
    "PrivateIpAddress": "192.168.7.3"
    "PrivateIpAddress": "192.168.10.41"
    "PrivateIpAddress": "192.168.1.124"
    "PrivateIpAddress": "192.168.14.253"
    "PrivateIpAddress": "192.168.13.47"
    "PrivateIpAddress": "192.168.7.48"
    "PrivateIpAddress": "192.168.26.225"
    "PrivateIpAddress": "192.168.9.243"
    "PrivateIpAddress": "192.168.8.246"
    "PrivateIpAddress": "192.168.7.183"


[ec2-user@ip-172-31-1-111 ekslab]$ kubectl get pod -o wide --all-namespaces | wc -l
39
```

### 7. Change WARM_IP_TARGET and WARM_ENI_TARGET
#### 7.1) Change WARM_IP_TARGET and WARM_ENI_TARGET
```
[ec2-user@ip-172-31-1-111 ekslab]$ kubectl set env daemonset -n kube-system aws-node WARM_IP_TARGET=2
daemonset.apps/aws-node env updated

[ec2-user@ip-172-31-1-111 ekslab]$ kubectl set env daemonset -n kube-system aws-node WARM_ENI_TARGET=0  [optional]
daemonset.apps/aws-node env updated

[ec2-user@ip-172-31-1-111 ekslab]$ kubectl set env daemonset -n kube-system aws-node  MINIMUM_IP_TARGET=8
daemonset.apps/aws-node env updated
```
Wait for a short time ( one minute )
```
[ec2-user@ip-172-31-1-111 ekslab]$ PNAME=$(kubectl get pod -n kube-system | grep -i aws-node | awk '{print $1}')
[ec2-user@ip-172-31-1-111 ekslab]$ for PP in ${PNAME}
> do
>     echo "Pod name -- ${PP}:"
>     kubectl describe pod ${PP} -n kube-system | grep -iE "WARM|MINIMUM"
>     echo -e ""
> done
Pod name -- aws-node-jl7t5:
      WARM_ENI_TARGET:                     0
      WARM_IP_TARGET:                      2
      MINIMUM_IP_TARGET:                   8

Pod name -- aws-node-nw5dk:
      WARM_ENI_TARGET:                     0
      WARM_IP_TARGET:                      2
      MINIMUM_IP_TARGET:                   8

Pod name -- aws-node-p9c2b:
      WARM_ENI_TARGET:                     0
      WARM_IP_TARGET:                      2
      MINIMUM_IP_TARGET:                   8
```

#### 7.2) Check again, how many ENI(s) have been used for worker nodes(EC2 instances) in EKS cluster
```
INSTANCE="i-0972868e0206d66d7 i-0d6e6ff8f456f8989 i-0e93c08b4dda4be18"
for INS in ${INSTANCE}
do
    echo "EC2 -- ${INS} is/are with ENI(s):"
    aws ec2 describe-instances --instance-ids ${INS} | jq .Reservations[0].Instances[0].NetworkInterfaces[].NetworkInterfaceId
    echo -e ""
done
```
```
[ec2-user@ip-172-31-1-111 ekslab]$ INSTANCE="i-0972868e0206d66d7 i-0d6e6ff8f456f8989 i-0e93c08b4dda4be18"
[ec2-user@ip-172-31-1-111 ekslab]$ for INS in ${INSTANCE}
> do
>     echo "EC2 -- ${INS} is/are with ENI(s):"
>     aws ec2 describe-instances --instance-ids ${INS} | jq .Reservations[0].Instances[0].NetworkInterfaces[].NetworkInterfaceId
>     echo -e ""
> done
EC2 -- i-0972868e0206d66d7 is/are with ENI(s):
"eni-0ff62bede9ad580a0"
"eni-064cb1574849630d6"

EC2 -- i-0d6e6ff8f456f8989 is/are with ENI(s):
"eni-09a6dce1c9dba60ba"
"eni-03cca927034df4220"

EC2 -- i-0e93c08b4dda4be18 is/are with ENI(s):
"eni-0c595eb3274d13e26"
"eni-0cb12e30d7a355c2b"
```

#### 7.3) Check again, How many IP(s) were assigned fore each worker node 
```
INSTANCE="i-0972868e0206d66d7 i-0d6e6ff8f456f8989 i-0e93c08b4dda4be18"
for INS in ${INSTANCE}
do
    echo "EC2 -- ${INS} is assigned IP(s):"
    aws ec2 describe-instances --instance-ids ${INS} | jq .Reservations[0].Instances[0].NetworkInterfaces[].PrivateIpAddresses | grep PrivateIpAddress | wc -l
    aws ec2 describe-instances --instance-ids ${INS} | jq .Reservations[0].Instances[0].NetworkInterfaces[].PrivateIpAddresses | grep PrivateIpAddress
    echo -e ""
done
```

```
[ec2-user@ip-172-31-1-111 ekslab]$ INSTANCE="i-0972868e0206d66d7 i-0d6e6ff8f456f8989 i-0e93c08b4dda4be18"
[ec2-user@ip-172-31-1-111 ekslab]$ for INS in ${INSTANCE}
> do
>     echo "EC2 -- ${INS} is assigned IP(s):"
>     aws ec2 describe-instances --instance-ids ${INS} | jq .Reservations[0].Instances[0].NetworkInterfaces[].PrivateIpAddresses | grep PrivateIpAddress | wc -l
>     aws ec2 describe-instances --instance-ids ${INS} | jq .Reservations[0].Instances[0].NetworkInterfaces[].PrivateIpAddresses | grep PrivateIpAddress
>     echo -e ""
> done
EC2 -- i-0972868e0206d66d7 is assigned IP(s):
10
    "PrivateIpAddress": "192.168.63.35"
    "PrivateIpAddress": "192.168.37.122"
    "PrivateIpAddress": "192.168.60.28"
    "PrivateIpAddress": "192.168.51.109"
    "PrivateIpAddress": "192.168.33.117"
    "PrivateIpAddress": "192.168.60.246"
    "PrivateIpAddress": "192.168.57.119"
    "PrivateIpAddress": "192.168.60.162"
    "PrivateIpAddress": "192.168.56.132"
    "PrivateIpAddress": "192.168.59.21"

EC2 -- i-0d6e6ff8f456f8989 is assigned IP(s):
10
    "PrivateIpAddress": "192.168.85.184"
    "PrivateIpAddress": "192.168.77.169"
    "PrivateIpAddress": "192.168.65.9"
    "PrivateIpAddress": "192.168.75.248"
    "PrivateIpAddress": "192.168.75.204"
    "PrivateIpAddress": "192.168.86.205"
    "PrivateIpAddress": "192.168.72.128"
    "PrivateIpAddress": "192.168.76.113"
    "PrivateIpAddress": "192.168.65.82"
    "PrivateIpAddress": "192.168.87.38"

EC2 -- i-0e93c08b4dda4be18 is assigned IP(s):
10
    "PrivateIpAddress": "192.168.5.84"
    "PrivateIpAddress": "192.168.1.195"
    "PrivateIpAddress": "192.168.9.150"
    "PrivateIpAddress": "192.168.25.121"
    "PrivateIpAddress": "192.168.19.220"
    "PrivateIpAddress": "192.168.11.36"
    "PrivateIpAddress": "192.168.10.223"
    "PrivateIpAddress": "192.168.1.120"
    "PrivateIpAddress": "192.168.19.172"
    "PrivateIpAddress": "192.168.23.65"
```

Per the description in [https://github.com/aws/amazon-vpc-cni-k8s](https://github.com/aws/amazon-vpc-cni-k8s):

If both **WARM_IP_TARGET** and **MINIMUM_IP_TARGET** are set, ipamd will attempt to meet both constraints. This environment variable **overrides** **WARM_ENI_TARGET** behavior.

So the WARM_IP_TARGET is key, please set the appropriate value for **WARM_IP_TARGET**, it will impact the free IP address for specific worker node.

