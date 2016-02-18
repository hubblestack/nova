grep:
  - tmp_partition:
      - path: /etc/fstab
      - pattern: /tmp
      - match: True #optional
      - found_success: True
      - tags:
          CentOS-6: CIS-1.1.1
      - description: |
        The /tmp directory is intended to be world-writable, which presents a risk
        of resource exhaustion if it is not bound to a separate partition.

  - tmp_partition_nodev:
      - path: /etc/fstab
      - pattern: /tmp
      - match: nodev
      - found_success: True
      - tags:
          CentOS-6: CIS-1.1.2
      - description: |
		Set the nodev option to ensure that users cannot create block or
        character devices in /tmp.

  - tmp_partition_nosuid:
      - path: /etc/fstab
      - pattern: /tmp
      - match: nosuid
      - found_success: True
      - tags:
          CentOS 6: CIS-1.1.3
      - description: |
		Set the nosuid option to ensure that users cannot create setuid files
        in /tmp.

  - tmp_partition_noexec:
      - path: /etc/fstab
      - pattern: /tmp
      - match: noexec
      - found_success: True
      - tags:
          CentOS 6: CIS-1.1.4
      - description: |
        Set the noexec option to ensure that users cannot execute binaries in /tmp.

  - var_partition:
      - path: /etc/fstab
      - pattern: /var
      - match: True
      - found_success: True
      - tags:
          CentOS-6: CIS-1.1.5
      - description: |
		The /var directory may contain world-writable files and directories,
        which presents a risk of resource exhaustion if it is not bound to a separate
        partition.

  - var_tmp_bind_mount:
      - path: /etc/fstab
      - pattern: ^/tmp
      - match: /var/tmp
      - found_success: True
      - tags:
          CentOS-6: CIS-1.1.6
      - description: |
        All programs that use /var/tmp and /tmp to read/write temporary files will
        always be written to the /tmp file system, preventing a user from running
        the /var file system out of space or trying to perform operations that have
        been blocked in the /tmp filesystem.

  - var_log_partition:
      - path: /etc/fstab
      - pattern: /var/log
      - match: True
      - found_success: True
      - tags:
          CentOS-6: CIS-1.1.7
      - description: |
        All programs that use /var/tmp and /tmp to read/write temporary files will
        always be written to the /tmp file system, preventing a user from running
        the /var file system out of space or trying to perform operations that have
        been blocked in the /tmp filesystem.

