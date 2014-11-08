// Despa Diana-Alexandra 321CA

#include "dns_message.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Portul pe care asculta serverul DNS.
#define PORT 53
#define LEN 256
#define MAX_LEN 514 // 512 + 2 octeti de lungime
// ID-ul mesajului DNS trimis.
#define THE_ANSWER 42
#define answers ";; ANSWER SECTION:\n"
#define auths ";; AUTHORITY SECTION:\n"
#define adds ";; ADDITIONAL SECTION:\n"
// Dimensiunea in octeti a unui resource record, fara campurile de dimensiune
// variabila.
#define rr_len 10

// Descriptorii fisierelor de log.
int messages, replies;

// Deschide o noua conexiune cu serverul "serv_addr".
// Intoarce 0 in caz de succes, -1 altfel.
int NewConnection(int *sockfd, struct sockaddr_in serv_addr) {
  if (*sockfd != 0)
    close(*sockfd);
  *sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (*sockfd < 0) {
    perror("ERROR opening socket");
    return -1;
  }
  struct timeval tv;
  tv.tv_sec = 5;
  tv.tv_usec = 0;
  // Setez timeout de 5 secunde pentru primirea de mesaje pe socket.
  setsockopt(*sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));
  if (connect(*sockfd, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) < 0) {
    perror("ERROR connecting");
    return -1;
  }
  return 0;
}

// Prefixeaza fiecare domeniu din adresa "ip" cu numarul de caractere(de octeti)
// pe care ii are acel domeniu. De exemplu: www.yahoo.com devine 3www5yahoo3com.
// Rezultatul acestei conversii este depus in variabila "new_ip". 
void DnsIpFormat(const char *ip, unsigned char *new_ip, int *len) {
  int domain_length = 0, i;
  memset(new_ip, 0, sizeof(new_ip));
  for (i = 0; i < strlen(ip) ; ++i) {
    if (ip[i] == '.') {
      new_ip[domain_length] = i - domain_length;
      *len = domain_length + 1;
      for(; domain_length < i; ++domain_length) {
        new_ip[(*len)++] = ip[domain_length];
      }
      new_ip[*len] = '\0';
      ++domain_length;
    }
  }
  new_ip[domain_length] = i - domain_length;
  *len = domain_length + 1;
  for(; domain_length < i; ++domain_length) {
    new_ip[(*len)++] = ip[domain_length];
  }
  new_ip[(*len)++] = 0;
}

// Adresa IP data ca parametru in variabila "ip" este inversata si ii este
// adaugat la sfarsit sirul "in-addr.arpa" pentru a forma numele de domeniu
// pentru reverse lookup.
void PTRFormat(const char *ip, unsigned char *new_ip, int *len) {
  *len = 0;
  int i;
  for (i = strlen(ip) - 1; i >= 0; --i) {
    new_ip[(*len)++] = ip[i];
  }
  strcat((char *)new_ip, ".in-addr.arpa");
  char *aux = strdup((char *)new_ip);
  DnsIpFormat(aux, new_ip, len);
  free(aux);
}

// Intoarce o adresa(url) extrasa din sirul "reply", care incepe unde pointeaza
// "iter" si calculeaza lungimea pe care o ocupa in cadrul "reply", rezultatul
// fiind valoarea variabilei "size". In interiorul sirului care desemneaza adresa
// se pot afla pointeri la alte locatii din cadrul "reply", astfel ca iteratorul
// poate realiza "salturi".
unsigned char *GetName(unsigned char *reply,
                       unsigned char *iter,
                       unsigned short *size) {
  unsigned char *name = (unsigned char *)calloc(LEN, sizeof(char));
  // In baza 2 : mask = 11000000;
  unsigned short mask = (1 << 7) + (1 << 6);
  unsigned short offset = 0, len = 0;
  int compressed = 0, i, j;
  
  *size = 1;
  while (*iter != 0) {  
    // Verific daca octetul la care am ajuns cu parcurgerea este inceputul unui
    // pointer.
    if (*iter >= mask) {
      // Determin offset-ul din "reply" la care se afla restul adresei scazand
      // valoarea cu reprezentarea 11000000 00000000 in binar din valoarea pe
      // 2 octeti de la adresa iter.
      offset = (iter[0] << 8) - (mask << 8) + iter[1];
      iter = reply + offset - 1;
      compressed = 1;
    } else {
      name[len++] = *iter; 
    }
    ++iter;
    if (compressed == 0) { // daca nu am sarit dimensiunea creste.
      ++(*size);
    }
  }
  
  name[len] = '\0';
  // Daca am sarit dimensiunea creste doar o data.
  if (compressed == 1) {
    ++(*size);
  }
  
  // Transform adresa "name" din notatia cu prefixe numerice pentru domenii
  // in notatia cu puncte. De exempul: 3www5yahoo3com trece in www.yahoo.com.
  for (i = 0; i < strlen((char *)name); ++i) {
    len = name[i];
    for (j = 0; j < len; ++j) {
      name[i] = name[i + 1];
      ++i;
    }
    name[i] = '.';
  }
  return name;
} 

// Intoarce denumirea clasei unui resource record in functie de identificatorul
// "rr".
char *class(unsigned short rr) {
  if (rr == 1)
    return "IN";
  if (rr == 2)
    return "CS";
  if (rr == 3)
    return "CH";
  if (rr == 4)
    return "HS";
  return NULL;
}

// Intoarce denumirea tipului unui resource record in functie de
// identificatorul "rr".
char *type(unsigned short rr) {
  switch (rr) {
  case A: return "A";
  case NS: return "NS";
  case CNAME: return "CNAME";
  case SOA: return "SOA";
  case PTR: return "PTR";
  case MX: return "MX";
  case TXT: return "TXT";
  default: return "OTHER_TYPE"; // Alt tip de inregistrare.
  }
}

// Extrage si scrie in fisierul "dns.log" continutul unui resource record la
// care pointeaza "rdata" in cadrul "reply", in functie de tipul lui. "len"
// reprezinta dimensiunea campului "rdata" din resource record.
void ExtractRdata(unsigned char *reply,
                  unsigned char *rdata,
                  unsigned short len,
                  unsigned short type) {
  if (type == A) {
    char address[15];
    sprintf(address, "%u.%u.%u.%u", rdata[0], rdata[1], rdata[2], rdata[3]);
    write(replies, address, strlen(address));
    return;
  }
  if (type == NS) {
    unsigned char *dname = GetName(reply, rdata, &type);
    write(replies, dname, strlen((char *)dname));
    free(dname);
    return;
  }
  if (type == CNAME) {
    unsigned char *cname = GetName(reply, rdata, &type);
    write(replies, cname, strlen((char *)cname));
    free(cname);
    return;
  }
  if (type == SOA) {
    unsigned short size = 0;
    unsigned char *mname = GetName(reply, rdata, &size);
    rdata += size;
    unsigned char *rname = GetName(reply, rdata, &size);
    rdata += size;
    unsigned int serial, refresh, retry, expire, minimum;
    memcpy(&serial, rdata, sizeof(serial));
    rdata += sizeof(serial);
    memcpy(&refresh, rdata, sizeof(refresh));
    rdata += sizeof(refresh);
    memcpy(&retry, rdata, sizeof(retry));
    rdata += sizeof(retry);
    memcpy(&expire, rdata, sizeof(expire));
    rdata += sizeof(expire);
    memcpy(&minimum, rdata, sizeof(minimum));
    serial = ntohl(serial);
    refresh = ntohl(refresh);
    retry = ntohl(retry);
    expire = ntohl(expire);
    minimum = ntohl(minimum);
    char line[MAX_LEN];
    sprintf(line, "%s\t%s\t%d\t%d\t%d\t%d\t%d",
                   mname, rname, serial, refresh, retry, expire, minimum);
    write(replies, line, strlen(line));
    free(mname);
    free(rname);
    return;
  }
  if (type == PTR) {
    unsigned char *dname = GetName(reply, rdata, &type);
    write(replies, dname, strlen((char *)dname));
    free(dname);
    return;
  }
  if (type == MX) {
    unsigned short pref;
    memcpy(&pref, rdata, sizeof(pref));
    pref = ntohs(pref);
    char exch[LEN];
    unsigned char *addr = GetName(reply, rdata + sizeof(pref), &type);
    sprintf(exch, "%u\t%s", pref, addr);
    write(replies, exch, strlen(exch));
    free(addr);
    return;
  }
  if (type == TXT) {
    write(replies, rdata, len);
    return;
  }
}

// Scrie in fisierul "dns.log" adresa, clasa si tipul unui resource record.
void PrintGeneralRR(unsigned char *name, char *class, char *type) {
  write(replies, name, strlen((char *)name));
  write(replies, "\t", 1);
  write(replies, class, strlen(class));
  write(replies, "\t", 1);
  write(replies, type, strlen(type));
  write(replies, "\t", 1);
}

// Scrie in fisierul "dns.log" toate informatiile despre un resource record.
// Intoarce noua pozitie a iteratorului "iter" in cadrul sirului "reply",
// aceasta modificandu-se prin parcurgerea informatiilor.
unsigned char *PrintRR(unsigned char *reply, unsigned char *iter) {
  unsigned char *name;
  char *rr_class, *rr_type;
  unsigned short size = 0;
  dns_rr_t *rr;
  
  name = GetName(reply, iter, &size);
  iter += size;
  rr = (dns_rr_t *)(iter);
  rr_class = class(ntohs(rr->class));
  rr_type = type(ntohs(rr->type));
  PrintGeneralRR(name, rr_class, rr_type);
  free(name);
  iter += rr_len;
  ExtractRdata(reply, iter, ntohs(rr->rdlength), ntohs(rr->type));
  iter += ntohs(rr->rdlength);
  write(replies, "\n", 1);
  return iter;
}

// Proceseaza raspunsul de la serverul DNS, din parametrul "reply", stiind ca
// header-ul si query-ul adresat mai inainte ocupa "length" octeti.
void ProcessDnsReply(unsigned char *reply, unsigned short length) {
  int answer_count = ntohs(((dns_header_t *)reply)->ancount),
      authority_count = ntohs(((dns_header_t *)reply)->nscount),
      additional_count = ntohs(((dns_header_t *)reply)->arcount);
  unsigned char *iter = reply + length;
  unsigned short i, offset = 2;
  
  // Deplasez pointerul la mesaj cu 2 octeti, trecand peste prefixul cu
  // dimensiunea lui.
  reply += offset; 
  
  // Afisez informatiile despre fiecare inregistrare din sectiunile "Answer",
  // "Authority" si "Additional".
  if (answer_count > 0) {
    write(replies, "\n", 1);
    write(replies, answers, strlen(answers));
  }
  for (i = 0; i < answer_count; ++i) {
    iter = PrintRR(reply, iter);
  }
  if (authority_count > 0) {
    write(replies, "\n", 1);
    write(replies, auths, strlen(auths));
  }
  for (i = 0; i < authority_count; ++i) {
    iter = PrintRR(reply, iter);
  }
  if (additional_count > 0) {
    write(replies, "\n", 1);
    write(replies, adds, strlen(adds));
  }
  for (i = 0; i < additional_count; ++i) {
    iter = PrintRR(reply, iter);
  }
  write(replies, "\n\n", 2);
}

// Scrie in fisierul "messages.log" continutul "msg" in format hexazecimal.
void HexPrint(unsigned char *msg) {
  int i;
  char str[3];
  for (i = 0; i < MAX_LEN; ++i) {
    sprintf(str, "%02X ", msg[i]);
    write(messages, str, strlen(str));
  }
}

// Scrie in fisierul "dns.log" adresa serverului DNS - "buff", adresa cautata -
// "arg1" si tipul query-ului - "arg2".
void PrintCommand(char *buff, char *arg1, char *arg2) {
  write(replies, "; ", 2);
  write(replies, buff, strlen(buff));
  write(replies, " - ", 3);
  write(replies, arg1, strlen(arg1));
  write(replies, " ", 1);
  write(replies, arg2, strlen(arg2));
  write(replies, "\n", 1);
}

int main(int argc, char *argv[]) {
  if (argc < 3 || argc >= 4) {
    fprintf(stderr,"Usage: %s <domain_name> <type>\n", argv[0]);
    return 1;
  }

  FILE *servers = fopen("dns_servers.conf", "r");
  messages = open("message.log", O_APPEND|O_WRONLY);
  replies = open("dns.log", O_APPEND|O_WRONLY);
  
  // Formez request-ul
  unsigned char *dns_msg = (unsigned char *)calloc(MAX_LEN, sizeof(char)),
      *dns_reply = (unsigned char *)calloc(MAX_LEN, sizeof(char));
  
  // Formez header-ul
  dns_header_t *header = (dns_header_t *)dns_msg;
  
  header->id = htons(THE_ANSWER);
  header->qr = 0;
  header->aa = 0;
  header->tc = 0;
  header->rd = 1;
  header->ra = 0;
  header->z = 0;
  header->rcode = 0;
  header->qdcount = htons(1); // un singur query
  header->ancount = 0;
  header->nscount = 0;
  header->arcount = 0;
  
  char *ip = argv[1];
  // Completez mesajul DNS cu numele query-ului
  unsigned char *qname = (unsigned char *)(dns_msg + sizeof(dns_header_t));
  int qname_len;
  
  // Formez query-ul
  dns_question_t *query;
  if (strcmp(argv[2], "PTR") == 0) {
    header->opcode = htons(1); // pentru reverse lookup
    PTRFormat(ip, qname, &qname_len);
    // Completez mesajul DNS continutul query-ului
    query = (dns_question_t *)(dns_msg + sizeof(dns_header_t) + qname_len);
    query->qtype = htons(PTR);
    
  } else {
    header->opcode = 0;
    DnsIpFormat(ip, qname, &qname_len);
    // Completez mesajul DNS continutul query-ului
    query = (dns_question_t *)(dns_msg + sizeof(dns_header_t) + qname_len);
    if (strcmp(argv[2], "A") == 0) {
      query->qtype = htons(A);
    } else if (strcmp(argv[2], "MX") == 0) {
      query->qtype = htons(MX);
    } else if (strcmp(argv[2], "NS") == 0) {
      query->qtype = htons(NS);
    } else if (strcmp(argv[2], "CNAME") == 0) {
      query->qtype = htons(CNAME);
    } else if (strcmp(argv[2], "SOA") == 0) {
      query->qtype = htons(SOA);
    } else if (strcmp(argv[2], "TXT") == 0) {
      query->qtype = htons(TXT);
    }
  }
  query->qclass = htons(1); // IN
  unsigned short length = sizeof(dns_header_t) +
                          sizeof(dns_question_t) +
                          qname_len;
  header->length = htons(length - 2);
  
  HexPrint(dns_msg); // scriu mesajul in fisierul "message.log"
  
  int sockfd = 0;
  struct sockaddr_in serv_addr;
  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(PORT);
  
  char buff[LEN];
  // Citeste pe rand cate o adresa IP din fisierul "dns_servers.conf", pana cand
  // se pot obtine informatii de la unul dintre serverele DNS.
  while (fgets(buff, sizeof(buff), servers) != 0) {
    if (buff[0] == '#' || buff[0] == '\n') {
      continue;
    }
    buff[strlen(buff) - 1] = '\0';
    inet_aton(buff, &serv_addr.sin_addr);
    if (NewConnection(&sockfd, serv_addr) < 0) {
      break;
    }
    if (send(sockfd, dns_msg, length, 0) <= 0) {
      perror("ERROR on send");
      return 1;
    }
    if (recv(sockfd, dns_reply, MAX_LEN, 0) < 0) {
      perror("ERROR on recv");
      continue;
    }
    if (((dns_header_t *)dns_reply)->rcode != 0) {
      printf("Error in received message: %d.\n",
          ((dns_header_t *)dns_reply)->rcode);
      continue;
    }
    
    // Scriu in fisierul "dns.log" adresa serverului DNS, adresa cautata si
    // tipul query-ului si procesez raspunsul.
    PrintCommand(buff, argv[1], argv[2]);
    ProcessDnsReply(dns_reply, length);
    break;
  } 
  
  free(dns_msg);
  free(dns_reply);
  fclose(servers);
  close(messages);
  close(replies);
  close(sockfd);
  return 0;
}
