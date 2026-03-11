FROM kalilinux/kali-rolling

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        nmap hping3 curl net-tools iputils-ping && \
    apt-get clean

COPY attack.sh /attack.sh
RUN chmod +x /attack.sh

CMD ["/attack.sh"]