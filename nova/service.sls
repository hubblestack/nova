service:
  blacklist:
    - chargen_dgram:
        - name: 
          CentOS: chargen-dgram
        - tags:
          FreeBSD-10.2: CIS-7.1
        - description:

    - chargen_stream:
        - name: 
          CentOS: chargen-stream
        - description: 
        - tags:
          CentOS 7: CIS.Cent7.1_1

    - daytime_dgram:
        - name: 
          CentOS: daytime_dgram
        - description: 
        - tags:
          CentOS 6: CIS.Cent6.8_2_1

    - daytime_stream:
        - name: 
          CentOS: daytime-stream
        - description: 
        - tags:
          CentOS 6: CIS.Cent6.8_2_1

    - echo_dgram:
        - name: 
          CentOS: echo-dgram
        - description: 
        - tags:
          CentOS 6: CIS.Cent6.8_2_1

    - echo_stream:
        - name: 
          CentOS: echo-stream
        - description: 
        - tags:
          CentOS 6: CIS.Cent6.8_2_1

    - avahi:
        - name: 
          CentOS: avahi-daemon
        - description: 
        - tags:
          CentOS 6: CIS.Cent6.8_2_1

    - dhcp_server:
        - name: 
          CentOS: dhcpd
        - description: 
        - tags:
          CentOS 6: CIS.Cent6.8_2_1

    - tcpmux_server:
        - name: 
          CentOS: tcpmux-server
        - description: 
        - tags:
          CentOS 6: CIS.Cent6.8_2_1

