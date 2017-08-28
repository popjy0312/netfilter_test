#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */
#include <errno.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <set>

#define MAX_URL_LEN 30
#define MAX_PAGE_LEN 100

using namespace std;

struct datas{
    char url[MAX_URL_LEN];

    bool operator < (const struct datas& tmp)const{
        return (memcmp(tmp.url, url, MAX_URL_LEN) > 0);
    }
};

set<struct datas> s;

void urlParse(char* fullUrl, char* url){
    u_int32_t port;
    char page[MAX_PAGE_LEN];

    if(!memcmp(fullUrl, "https", 5)){
        if(sscanf(fullUrl,"https://%99[^:]:%d/%99[^\n]", url, &port, page) != 3){
            if(sscanf(fullUrl, "https://%99[^/]/%99[^\n]", url, page) != 2){
                if(sscanf(fullUrl, "https://%99[^:]:%d", url, &port) != 2){
                    if(sscanf(fullUrl, "https://%99[^/]/", url) != 1){
                        sscanf(fullUrl, "%99[^\n]\n",url);
                    }
                }
            }
        }
    }
    else if(!memcmp(fullUrl, "http", 4)){
        if(sscanf(fullUrl,"http://%99[^:]:%d/%99[^\n]", url, &port, page) != 3){
            if(sscanf(fullUrl, "http://%99[^/]/%99[^\n]", url, page) != 2){
                if(sscanf(fullUrl, "http://%99[^:]:%d", url, &port) != 2){
                    if(sscanf(fullUrl, "http://%99[^/]/", url) != 1){
                        sscanf(fullUrl, "%99[^\n]\n",url);
                    }
                }
            }
        }
    }
    else{
        memset(url, 0, MAX_URL_LEN);
    }
}

void initSet(){
    FILE* f;
    u_int32_t ret;
    char strtmp[MAX_URL_LEN];
    char strtmp2[MAX_URL_LEN];
    struct datas data;

    if( (f= fopen("filter_lists.txt","r")) == NULL){
        printf("File Open Fail\n");
        exit(1);
    }

    while( (ret = fscanf(f, "%s", strtmp)) != EOF){
        memset(data.url, 0, MAX_URL_LEN);
        memset(strtmp2, 0, MAX_URL_LEN);
        urlParse(strtmp, strtmp2);
        memcpy(data.url, strtmp2, strlen(strtmp2));
        s.insert(data);
        printf("Insert data %s\n", strtmp2);
        printf("Set Size: %d\n",(u_int32_t)s.size());
    }

    fclose(f);
}

void parseIP(unsigned char *data, char *pdropFlag){
    struct ip *pip = (struct ip*)data;
    struct tcphdr* ptcp_hdr;
    unsigned char *phttp;
    u_int32_t httpLen;
    u_int32_t idx = 0;
    u_int32_t url_fin;
    struct datas urldata;

    if (pip->ip_p == IPPROTO_TCP){
        ptcp_hdr = (struct tcphdr*)(data + pip->ip_hl*4);
        phttp = (unsigned char*)(data + pip->ip_hl*4 + ptcp_hdr->doff*4);
        httpLen = (uint32_t)htons(pip->ip_len) - (uint32_t)pip->ip_hl*4-(uint32_t)ptcp_hdr->doff*4;

        for(idx = 0;idx < httpLen;idx++){
            if(!memcmp( phttp + idx , "Host: ", 6)){
                idx += 6;

                for(url_fin = idx; url_fin < httpLen; url_fin++){
                    if( *(phttp + url_fin) == '\r')
                        break;
                }

                memset(urldata.url, 0, MAX_URL_LEN);
                memcpy(urldata.url, phttp + idx, url_fin - idx);
                printf("\n###########################\n%s\n##############################\n",urldata.url);

                if(s.find(urldata) != s.end())
                    *pdropFlag = 1;
                    return;

                break;
            }
        }
    }

    *pdropFlag = 0;
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb, char *pdropFlag)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
            ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0)
        printf("payload_len=%d ", ret);

    parseIP(data, pdropFlag);
    fputc('\n', stdout);

    return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    char dropFlag = 0;
    u_int32_t id = print_pkt(nfa, &dropFlag);
    if(dropFlag == 1){
        printf("Drop!\n");
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
    else{
        printf("entering callback\n");
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    initSet();

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. Please, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}

