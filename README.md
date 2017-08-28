# netfilter_test

BoB 6기 취약점트랙 정주영.

이경문멘토님 과제.

## [리포트] 
iptables, netfilter를 이용하여 간단한 웹 방화벽을 구현하라.

## [프로그램]
netfilter_test

## [학습]

iptables 및 netfilter 사용 방법을 익힌다.

[iptables](https://gitlab.com/…/…/wikis/iptables-and-netfilter/iptables)

[netfilter](https://gitlab.com/…/network/wikis/iptables-and-n…/netfilter)

nfqnl_test.c 예제에서 nfq_get_payload 함수가 수행이 되면 패킷의 IP header 시작 위치가 data라는 포인터 변수에 넘어 온다. 이후 IP, TCP, Data(HTTP)를 파싱하여 Host의 값이 유해 사이트(avnana.com)인 경우 차단(nfq_set_verdict(..., NF_DROP, ...))을 하고 나머지 경우에는 허용을 하도록 코딩을 작성하여 실제로 avnana.com 사이트가 차단이 되는지 확인해 본다.

이후 유해 사이트를 여러개(최소 수십개)로 입력받을 수 있도록 하여 여러 사이트들이 제대로 차단이 되는지를 확인해 본다(유해 사이트 목록은 각자 알아서).
