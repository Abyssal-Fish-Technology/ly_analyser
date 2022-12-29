#!/bin/bash
#sleep 12
now=`date +"%s"`
aligned_now=$[$now-$now%300-300]
echo $aligned_now

endtime=$[$aligned_now-3600*24]
#endtime=$[$aligned_now]
while [ $endtime -le $aligned_now ]
do
  #cmd="/Agent/bin/extractor -v 1 -t $endtime -n"
  cmd="sudo -u apache ./extractor -v 1 -t $endtime -i ./indexer"
  #cmd="sudo -u apache DEBUG=ALL ./extractor -v 1 -t $endtime -i ./indexer"
  echo $cmd
  $cmd 
  endtime=$[$endtime+300]
done
