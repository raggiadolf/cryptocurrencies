docker build -t hashparty .

docker rm -f $(docker ps -aq)

for i in {59192..59202}
do
	docker run -d -e hashport=${i} --name hashparty$i -p ${i}:${i}/udp hashparty
done