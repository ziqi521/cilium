#!/usr/bin/env bash

SRC_ID=$1
DST_ID=$2

SRC_POD=$(kubectl get pods -l id=${SRC_ID} -o jsonpath='{.items[0].metadata.name}')
DST_IP=$(kubectl get svc ${SRC_ID}-service -o jsonpath='{.spec.clusterIP}')

kubectl exec $SRC_POD -- curl -s $DST_IP
