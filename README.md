# bandwidth_statistics
bandwidth statistics lan client traffic for router.Has passed the test on the 3.10 kernel
this module for router,or openwrt
make 
insmod bw_info.ko
cat /proc/net/bandwidth_upload
cat /proc/net/bandwidth_download
