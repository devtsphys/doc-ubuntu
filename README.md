# Ubuntu & Shell Scripting Reference Card

- [Basic Terminal Navigation](#basic-terminal-navigation)
- [File Permisssions](#file-permissions)

## Basic Terminal Navigation

| Command | Description | Examples |
|---------|-------------|----------|
| `pwd` | Print working directory | `pwd` → `/home/user` |
| `ls` | List directory contents | `ls -la` (shows all files with details) |
| `cd` | Change directory | `cd Documents`, `cd ..` (parent directory), `cd ~` (home) |
| `mkdir` | Create directory | `mkdir new_folder` |
| `rm` | Remove files/directories | `rm file.txt`, `rm -r folder/` (recursive), `rm -rf folder/` (force) |
| `cp` | Copy files/directories | `cp file.txt backup.txt`, `cp -r dir1/ dir2/` |
| `mv` | Move/rename files | `mv file.txt newname.txt`, `mv file.txt ~/Documents/` |
| `touch` | Create empty file | `touch newfile.txt` |
| `cat` | Display file contents | `cat file.txt` |
| `less` | View file with pagination | `less large_file.txt` (use q to exit) |
| `head`/`tail` | Show beginning/end of file | `head -n 10 file.txt`, `tail -f log.txt` (follow) |
| `find` | Search for files | `find /home -name "*.txt"` |
| `grep` | Search text patterns | `grep "pattern" file.txt`, `grep -r "text" /dir/` (recursive) |

## File Permissions

| Command | Description | Examples |
|---------|-------------|----------|
| `chmod` | Change file permissions | `chmod 755 script.sh`, `chmod +x script.sh` (make executable) |
| `chown` | Change file owner | `chown user:group file.txt` |
| `umask` | Set default permissions | `umask 022` (default is usually 022) |

Permission Numeric Values:
- 4: Read (r)
- 2: Write (w)
- 1: Execute (x)

Common Permission Combinations:
- 755 (rwxr-xr-x): Owner can read/write/execute, others can read/execute
- 644 (rw-r--r--): Owner can read/write, others can read
- 700 (rwx------): Owner can read/write/execute, others have no access

## Process Management

| Command | Description | Examples |
|---------|-------------|----------|
| `ps` | Show process status | `ps aux` (all processes), `ps -ef` (full format) |
| `top`/`htop` | Process monitoring | `top`, `htop` (more interactive) |
| `kill` | Terminate process | `kill PID`, `kill -9 PID` (force kill) |
| `pkill` | Kill process by name | `pkill firefox` |
| `bg` | Send process to background | `bg` |
| `fg` | Bring process to foreground | `fg` |
| `jobs` | List background jobs | `jobs` |
| `nohup` | Run command immune to hangups | `nohup command &` |
| `&` | Run process in background | `command &` |
| `pgrep` | Find process ID by name | `pgrep firefox` |

## System Information

| Command | Description | Examples |
|---------|-------------|----------|
| `uname` | System information | `uname -a` (all info) |
| `lsb_release` | Ubuntu version | `lsb_release -a` |
| `df` | Disk space usage | `df -h` (human-readable) |
| `du` | Directory space usage | `du -sh directory/` (summary, human-readable) |
| `free` | Memory usage | `free -h` (human-readable) |
| `lsblk` | List block devices | `lsblk` |
| `lshw` | Hardware information | `sudo lshw` |
| `lscpu` | CPU information | `lscpu` |
| `ifconfig`/`ip` | Network interfaces | `ifconfig`, `ip addr` |
| `lsof` | List open files | `lsof -i :80` (check port 80) |
| `dmesg` | Kernel messages | `dmesg` |

## Package Management (APT)

| Command | Description | Examples |
|---------|-------------|----------|
| `apt update` | Update package lists | `sudo apt update` |
| `apt upgrade` | Upgrade packages | `sudo apt upgrade` |
| `apt install` | Install package | `sudo apt install package_name` |
| `apt remove` | Remove package | `sudo apt remove package_name` |
| `apt purge` | Remove package and configs | `sudo apt purge package_name` |
| `apt search` | Search packages | `apt search keyword` |
| `apt show` | Show package details | `apt show package_name` |
| `apt list` | List packages | `apt list --installed` |
| `apt autoremove` | Remove unused dependencies | `sudo apt autoremove` |
| `dpkg -i` | Install .deb file | `sudo dpkg -i package.deb` |
| `add-apt-repository` | Add PPA | `sudo add-apt-repository ppa:name/ppa` |

## Text Processing

| Command | Description | Examples |
|---------|-------------|----------|
| `grep` | Search for pattern | `grep "pattern" file.txt`, `grep -i` (case insensitive) |
| `sed` | Stream editor | `sed 's/old/new/g' file.txt` (substitute) |
| `awk` | Text processing | `awk '{print $1}' file.txt` (print first column) |
| `cut` | Extract sections | `cut -d ',' -f 1 file.csv` (1st field, comma delimiter) |
| `sort` | Sort lines | `sort file.txt`, `sort -n` (numeric), `sort -r` (reverse) |
| `uniq` | Remove duplicates | `sort file.txt \| uniq` |
| `wc` | Count lines/words/chars | `wc -l file.txt` (line count) |
| `tr` | Translate characters | `cat file.txt \| tr '[a-z]' '[A-Z]'` (uppercase) |
| `diff` | Compare files | `diff file1.txt file2.txt` |
| `tee` | Read from stdin, write to stdout/files | `command \| tee file.txt` |

## Redirection & Pipes

| Symbol | Description | Examples |
|--------|-------------|----------|
| `>` | Redirect stdout (overwrite) | `ls > files.txt` |
| `>>` | Redirect stdout (append) | `echo "text" >> file.txt` |
| `<` | Redirect stdin | `sort < unsorted.txt` |
| `2>` | Redirect stderr | `command 2> errors.log` |
| `2>&1` | Redirect stderr to stdout | `command > output.txt 2>&1` |
| `\|` | Pipe output to next command | `ls \| grep ".txt"` |
| `/dev/null` | Discard output | `command > /dev/null 2>&1` |

## Shell Scripting Basics

### Script Header
```bash
#!/bin/bash
# Description: My script
```

### Variables
```bash
NAME="Ubuntu"         # Define variable (no spaces around =)
echo $NAME            # Use variable
echo "${NAME}_user"   # Use variable in string
readonly CONST="value" # Constant variable
```

### Command Substitution
```bash
current_dir=$(pwd)    # New style
date_old=`date`       # Old style
```

### Math Operations
```bash
result=$((5 + 3))     # Arithmetic expansion
let sum=10+20         # Using let
expr 5 + 3            # Using expr (spaces required)
```

### Conditional Statements
```bash
if [ "$a" -eq "$b" ]; then
    echo "a equals b"
elif [ "$a" -gt "$b" ]; then
    echo "a is greater than b"
else
    echo "a is less than b"
fi

# Modern test syntax
if [[ "$string" == *wild* ]]; then
    echo "Pattern matched"
fi
```

### Comparison Operators
Numeric:
- `-eq` (equal)
- `-ne` (not equal)
- `-gt` (greater than)
- `-lt` (less than)
- `-ge` (greater than or equal)
- `-le` (less than or equal)

String:
- `==` (equal)
- `!=` (not equal)
- `-z` (empty string)
- `-n` (not empty string)

File tests:
- `-e` (exists)
- `-f` (regular file)
- `-d` (directory)
- `-r` (readable)
- `-w` (writable)
- `-x` (executable)

### Loops

For loop:
```bash
for i in 1 2 3 4 5; do
    echo "Number: $i"
done

# Range
for i in {1..5}; do
    echo "Number: $i"
done

# C-style
for ((i=0; i<5; i++)); do
    echo "Number: $i"
done
```

While loop:
```bash
count=0
while [ $count -lt 5 ]; do
    echo "Count: $count"
    ((count++))
done
```

Until loop:
```bash
count=0
until [ $count -ge 5 ]; do
    echo "Count: $count"
    ((count++))
done
```

### Case Statement
```bash
case "$option" in
    start)
        echo "Starting service"
        ;;
    stop)
        echo "Stopping service"
        ;;
    restart|reload)
        echo "Restarting service"
        ;;
    *)
        echo "Usage: $0 {start|stop|restart}"
        ;;
esac
```

### Functions
```bash
# Define function
my_function() {
    echo "Parameter 1: $1"
    local local_var="I'm local"  # Local variable
    return 0  # Return status
}

# Call function
my_function "parameter"
```

### Input & Output
```bash
# Read user input
echo "Enter name:"
read name
echo "Hello, $name"

# Read with prompt
read -p "Enter age: " age

# Read secret
read -sp "Password: " password
echo

# Read into array
read -a arr -p "Enter items: "
echo "First item: ${arr[0]}"
```

### Arrays
```bash
# Define array
fruits=("apple" "banana" "cherry")

# Access element
echo ${fruits[1]}  # banana

# All elements
echo ${fruits[@]}

# Array length
echo ${#fruits[@]}

# Add element
fruits+=("orange")

# Iterate
for fruit in "${fruits[@]}"; do
    echo "$fruit"
done
```

### String Operations
```bash
str="Ubuntu Linux"

# Length
echo ${#str}

# Substring (position, length)
echo ${str:0:6}  # Ubuntu

# Replace
echo ${str/Ubuntu/Debian}  # Debian Linux

# Replace all occurrences
echo ${str//u/U}

# Check if starts with
if [[ "$str" == Ubuntu* ]]; then
    echo "Starts with Ubuntu"
fi
```

## Advanced Shell Features

### Error Handling
```bash
# Exit on error
set -e

# Exit on unbound variable
set -u

# Trap errors
trap 'echo "Error on line $LINENO"; exit 1' ERR

# Custom error function
error() {
    echo "ERROR: $1" >&2
    exit 1
}
```

### Process Substitution
```bash
diff <(ls dir1) <(ls dir2)
```

### Here Documents
```bash
cat << EOF > file.txt
This is line 1
This is line 2
EOF
```

### Brace Expansion
```bash
echo {1..5}         # 1 2 3 4 5
echo {a..e}         # a b c d e
echo file{1,2,3}.txt # file1.txt file2.txt file3.txt
mkdir -p project/{src,docs,tests}
```

### Parameter Substitution
```bash
# Default value if unset
echo ${var:-default}

# Assign default if unset
echo ${var:=default}

# Error if unset
echo ${var:?error}

# Use alternate if set
echo ${var:+alternate}
```

### Command Shortcuts

| Shortcut | Description |
|----------|-------------|
| `Ctrl+C` | Interrupt (kill) current process |
| `Ctrl+Z` | Suspend current process |
| `Ctrl+D` | End of file/input |
| `Ctrl+L` | Clear screen |
| `Ctrl+A` | Move cursor to beginning of line |
| `Ctrl+E` | Move cursor to end of line |
| `Ctrl+U` | Cut from cursor to beginning of line |
| `Ctrl+K` | Cut from cursor to end of line |
| `Ctrl+W` | Cut word before cursor |
| `Ctrl+Y` | Paste previously cut text |
| `Ctrl+R` | Search command history |
| `!!` | Repeat last command |
| `!$` | Last argument of previous command |
| `!*` | All arguments of previous command |
| `!string` | Most recent command starting with "string" |
| `Alt+.` | Insert last argument of previous command |


## System Information & Management

### System Details
```bash
# System/kernel information
uname -a                 # All system info
lsb_release -a           # Ubuntu version info
cat /etc/os-release      # Distribution details
hostnamectl              # System and OS details

# Hardware information
lscpu                    # CPU details
free -h                  # Memory usage
lsblk                    # Block devices
df -h                    # Disk usage
lspci                    # PCI devices
lsusb                    # USB devices
```

### Process Management
```bash
ps aux                   # List all running processes
top                      # Interactive process viewer
htop                     # Enhanced interactive process viewer
pgrep firefox            # Find process ID by name
pkill firefox            # Kill process by name
kill -9 1234             # Force kill process with PID 1234
nice -n 10 command       # Run command with adjusted priority
renice -n 10 -p 1234     # Change priority of running process
nohup command &          # Run command immune to hangups
```

### System Control
```bash
shutdown -h now          # Shutdown immediately
reboot                   # Restart system
systemctl poweroff       # Power off
systemctl reboot         # Reboot
systemctl suspend        # Suspend to RAM
systemctl hibernate      # Suspend to disk
```

## Package Management

### APT Commands
```bash
apt update               # Update package lists
apt upgrade              # Upgrade all packages
apt full-upgrade         # Upgrade with package removal if needed
apt install package      # Install a package
apt remove package       # Remove a package
apt purge package        # Remove package and configurations
apt autoremove           # Remove unused dependencies
apt search keyword       # Search for packages
apt show package         # Show package details
apt list --installed     # List installed packages
```

### APT Advanced
```bash
apt install ./file.deb           # Install local .deb file
apt install package=1.2.3-0ubuntu1  # Install specific version
apt-mark hold package            # Prevent package from upgrading
apt-mark unhold package          # Allow package to upgrade again
```

### PPAs & Third-Party Repositories
```bash
add-apt-repository ppa:name/ppa  # Add PPA repository
add-apt-repository --remove ppa:name/ppa  # Remove PPA

# Manually add repository
echo "deb http://repo.example.com/ubuntu focal main" | sudo tee /etc/apt/sources.list.d/example.list

# Add repository key
curl -fsSL https://repo.example.com/key.gpg | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/example.gpg
```

### Dpkg (Low-level Package Tool)
```bash
dpkg -i package.deb      # Install a .deb file
dpkg -r package          # Remove package
dpkg -P package          # Purge package
dpkg -l                  # List installed packages
dpkg -L package          # List files installed by package
dpkg -S /path/to/file    # Find which package owns a file
```

### Snap Package Management
```bash
snap list                # List installed snaps
snap find name           # Find snap packages
snap install name        # Install a snap
snap refresh name        # Update a snap
snap remove name         # Remove a snap
snap info name           # Show details about a snap
```

## File System

### Navigation & File Operations
```bash
pwd                      # Print working directory
ls -la                   # List all files with details
cd /path/to/dir          # Change directory
mkdir -p dir1/dir2       # Create directory tree
rmdir dir                # Remove empty directory
rm file                  # Remove file
rm -r dir                # Remove directory and contents
cp file1 file2           # Copy file
cp -r dir1 dir2          # Copy directory recursively
mv file1 file2           # Move/rename file
ln -s target link        # Create symbolic link
```

### File Permissions
```bash
chmod 755 file           # Change file mode (numeric)
chmod u+x file           # Add execute permission for user
chmod g-w file           # Remove write permission for group
chmod a+r file           # Add read permission for all
chmod -R 755 dir         # Recursively change permissions
chown user:group file    # Change file owner and group
chown -R user:group dir  # Recursively change ownership
```

### File Search & Text Processing
```bash
find /path -name "*.txt"  # Find files by name
find /path -type f -size +10M  # Find files larger than 10MB
find /path -mtime -7     # Files modified in last 7 days
grep "pattern" file      # Search for pattern in file
grep -r "pattern" /path  # Recursive search
locate filename          # Locate files (needs updatedb)

# Text processing
cat file                 # Output file contents
less file                # View file with paging
head -n 10 file          # Show first 10 lines
tail -n 10 file          # Show last 10 lines
tail -f /var/log/syslog  # Follow file updates
wc -l file               # Count lines in file
sort file                # Sort lines in file
uniq file                # Remove duplicate lines
cut -d: -f1 file         # Cut first field using : delimiter
sed 's/old/new/g' file   # Replace text
awk '{print $1}' file    # Print first column
```

### File Compression
```bash
tar -cf archive.tar files        # Create tar archive
tar -xf archive.tar              # Extract tar archive
tar -czf archive.tar.gz files    # Create compressed tar archive
tar -xzf archive.tar.gz          # Extract compressed tar archive
tar -cjf archive.tar.bz2 files   # Create bzip2 compressed archive
tar -xjf archive.tar.bz2         # Extract bzip2 compressed archive
zip -r archive.zip directory     # Create zip archive
unzip archive.zip                # Extract zip archive
gzip file                        # Compress file with gzip
gunzip file.gz                   # Decompress gzip file
```

## Users & Permissions

### User Management
```bash
who                      # Show who is logged in
whoami                   # Show current user
id                       # Show user and group IDs
sudo command             # Execute command as superuser
su - username            # Switch to another user
passwd                   # Change current user password
passwd username          # Change another user's password

# User administration
useradd -m username      # Create user with home directory
usermod -aG group user   # Add user to group
userdel -r username      # Delete user and home directory
groupadd groupname       # Create a new group
groupdel groupname       # Delete a group
```

### Sudo & Privileges
```bash
sudo -i                  # Get root shell
sudo -l                  # List user's sudo privileges
visudo                   # Edit sudoers file safely

# Add user to sudoers
echo "username ALL=(ALL) ALL" | sudo tee /etc/sudoers.d/username
chmod 440 /etc/sudoers.d/username
```

## Networking

### Network Configuration
```bash
ip a                     # Show IP addresses
ip r                     # Show routing table
ip link set eth0 up/down # Enable/disable interface
ifconfig                 # Show interfaces (legacy)
iwconfig                 # Show wireless interfaces

# NetworkManager CLI
nmcli device wifi list   # List available WiFi networks
nmcli device wifi connect SSID password PASSWORD  # Connect to WiFi
nmcli connection show    # Show connections
nmcli connection up/down "connection name"  # Enable/disable connection
```

### Network Testing & Troubleshooting
```bash
ping host                # ICMP echo request
traceroute host          # Show route to host
mtr host                 # Interactive traceroute
dig domain.com           # DNS lookup
nslookup domain.com      # DNS lookup (legacy)
host domain.com          # DNS lookup (simpler)
whois domain.com         # WHOIS domain lookup
ss -tuln                 # Show listening ports
netstat -tuln            # Show listening ports (legacy)
nc -vz host port         # Test TCP connection
curl ifconfig.me         # Show public IP address
```

### Firewall (UFW)
```bash
ufw status               # Check firewall status
ufw enable/disable       # Enable/disable firewall
ufw allow 22/tcp         # Allow SSH port
ufw deny 80/tcp          # Block HTTP port
ufw allow from 192.168.1.0/24 to any port 22  # Allow SSH from subnet
ufw delete allow 80/tcp  # Remove rule
```

## Services & Startup

### Systemd Service Management
```bash
systemctl start service    # Start service
systemctl stop service     # Stop service
systemctl restart service  # Restart service
systemctl reload service   # Reload configuration
systemctl enable service   # Start at boot
systemctl disable service  # Don't start at boot
systemctl status service   # Check service status
systemctl list-units --type=service  # List all services
```

### Service Logs
```bash
journalctl                              # View all logs
journalctl -u service                   # View service logs
journalctl -f                           # Follow new log messages
journalctl --since "1 hour ago"         # Show recent logs
journalctl -b                           # Show logs since boot
journalctl -p err                       # Show error messages
```

### Boot & Startup
```bash
systemd-analyze                        # Boot time analysis
systemd-analyze blame                  # Show boot time by unit
systemd-analyze critical-chain         # Show boot chain
update-grub                            # Update GRUB config
```

## Storage Management

### Disk Operations
```bash
fdisk -l                # List disks and partitions
parted -l               # List partitions (GPT support)
gdisk /dev/sda          # GPT partition editor
fdisk /dev/sda          # MBR partition editor
mkfs.ext4 /dev/sda1     # Format partition as ext4
mkfs.xfs /dev/sda1      # Format partition as XFS
mkswap /dev/sda2        # Create swap space
swapon /dev/sda2        # Enable swap
```

### Logical Volume Management (LVM)
```bash
pvdisplay               # Show physical volumes
vgdisplay               # Show volume groups
lvdisplay               # Show logical volumes

# LVM creation
pvcreate /dev/sdb       # Create physical volume
vgcreate vg0 /dev/sdb   # Create volume group
lvcreate -L 10G -n lv0 vg0  # Create logical volume
mkfs.ext4 /dev/vg0/lv0  # Format logical volume

# LVM resizing
lvextend -L +5G /dev/vg0/lv0  # Extend logical volume
resize2fs /dev/vg0/lv0        # Resize filesystem
```

### Mounts & fstab
```bash
mount /dev/sda1 /mnt    # Mount device temporarily
mount -a                # Mount all in fstab
umount /mnt             # Unmount filesystem

# fstab entry example
# UUID=xxxx-xxxx /mount/point filesystem defaults 0 2
blkid                   # Show block device attributes
findmnt                 # Show mounted filesystems
```

## Shell & Terminal

### Shell Operations
```bash
history                 # Command history
!!                      # Repeat last command
!n                      # Repeat command n from history
!string                 # Repeat last command starting with string
Ctrl+R                  # Reverse search command history
Ctrl+A/E                # Move to beginning/end of line
Ctrl+U/K                # Cut from cursor to beginning/end of line
```

### Job Control
```bash
command &               # Run command in background
jobs                    # List background jobs
fg %n                   # Bring job n to foreground
bg %n                   # Send job n to background
Ctrl+Z                  # Suspend foreground process
kill %n                 # Kill job n
```

### Shell Configuration
```bash
echo $PATH              # Show executable search path
export PATH=$PATH:/new/dir  # Add to PATH temporarily
source ~/.bashrc        # Reload bashrc configuration
alias ll='ls -la'       # Create command alias
```

## System Monitoring

### Performance Monitoring
```bash
uptime                  # System load and uptime
w                       # Who is logged in and what they're doing
vmstat 1                # Virtual memory statistics (every second)
iostat 1                # I/O statistics (every second)
mpstat -P ALL 1         # CPU statistics (every second)
sar -n DEV 1            # Network statistics (every second)
```

### Resource Monitoring
```bash
free -h                 # Memory usage
df -h                   # Disk space usage
du -sh /path            # Directory size
dmesg                   # Kernel ring buffer messages
dmesg -w                # Follow kernel messages
lsof                    # List open files
lsof -i :80             # What's using port 80
fuser -m /mount/point   # Who's using a mount point
```

## Security

### SSH Operations
```bash
ssh user@host           # Connect to host as user
ssh -p 2222 user@host   # Connect on specific port
ssh-keygen              # Generate SSH key pair
ssh-copy-id user@host   # Copy SSH key to host

# SSH config (~/.ssh/config)
# Host alias
#     HostName server.example.com
#     User username
#     Port 2222
```

### File Integrity & Security
```bash
sha256sum file          # Generate SHA256 checksum
md5sum file             # Generate MD5 checksum (less secure)
gpg -c file             # Encrypt file
gpg file.gpg            # Decrypt file
gpg --gen-key           # Generate GPG key
```

## Advanced Techniques

### Scheduling Tasks
```bash
crontab -e              # Edit user crontab
crontab -l              # List user crontab jobs

# crontab format:
# min hour day month weekday command
# 0 5 * * * /path/to/script  # Run at 5am daily

at 10:00                # Schedule one-time task at 10:00
atq                     # List scheduled at jobs
atrm n                  # Remove at job n
```

### Scripting Tools
```bash
screen                  # Terminal multiplexer
screen -S name          # Start named screen session
screen -r name          # Reattach to screen session
screen -ls              # List screen sessions
Ctrl+a d                # Detach from screen

tmux                    # Modern terminal multiplexer
tmux new -s name        # Start named tmux session
tmux attach -t name     # Attach to tmux session
tmux ls                 # List tmux sessions
Ctrl+b d                # Detach from tmux
```

### System Backup
```bash
rsync -avz /src /dest           # Sync files locally
rsync -avz -e ssh /src user@host:/dest  # Sync over SSH
dd if=/dev/sda of=/path/backup.img  # Disk image backup
```

## Troubleshooting

### Log Files
```bash
/var/log/syslog         # System logs
/var/log/auth.log       # Authentication logs
/var/log/dmesg          # Boot messages
/var/log/kern.log       # Kernel logs
/var/log/apache2/       # Apache logs
/var/log/apt/           # APT logs
```

### Debug Tools
```bash
strace command          # Trace system calls
ltrace command          # Trace library calls
ldd /path/to/binary     # Show shared library dependencies
```

## Best Practices

### Security
- Keep your system updated: `sudo apt update && sudo apt upgrade`
- Use strong passwords and consider password manager
- Use SSH keys instead of passwords
- Configure firewall with UFW
- Apply principle of least privilege
- Regularly audit user accounts and installed packages
- Consider disk encryption for sensitive data

### System Maintenance
- Regular updates (weekly at minimum)
- Create regular backups
- Monitor disk space and clean up when needed
- Periodically check for failed services: `systemctl --failed`
- Review logs for anomalies
- Set up unattended security updates: `apt install unattended-upgrades`

### Performance
- Use LTS versions for stability
- Adjust swappiness for your workload
- Use appropriate filesystem for your needs
- Monitor resource usage regularly
- Consider SSD TRIM scheduling if using SSDs

### Software Installation
- Prefer official repositories and PPAs over random .deb files
- Consider using containers or snaps for isolation
- Remove unused software regularly
- Check for recommended dependencies during installation



## Bash Scripting Reference Card

## Basic Script Structure

```bash
#!/bin/bash
# This is a comment
echo "Hello World"
```

- First line (`#!/bin/bash`) is called the shebang - it tells the system which interpreter to use
- Make scripts executable with `chmod +x script.sh`
- Run with `./script.sh` or `bash script.sh`

## Variables

```bash
# Assignment (no spaces around =)
name="John"
age=30

# Access with $
echo "Name: $name, Age: $age"

# Command substitution
current_date=$(date)
files_count=$(ls | wc -l)

# Arithmetic
result=$((5 + 3))
```

## Input and Output

```bash
# User input
read -p "Enter your name: " user_name
read -s -p "Enter password: " password  # -s for silent/hidden input

# Output to terminal
echo "Standard output"
echo "Error message" >&2  # Write to stderr

# Redirecting output
ls > file_list.txt        # Redirect stdout to file (overwrite)
ls >> file_list.txt       # Append stdout to file
ls 2> errors.txt          # Redirect stderr to file
ls &> all_output.txt      # Redirect both stdout and stderr
```

## Conditionals

```bash
# If statement
if [ "$name" = "John" ]; then
    echo "Hello John"
elif [ "$name" = "Jane" ]; then
    echo "Hello Jane"
else
    echo "Hello stranger"
fi

# Test command alternatives
# [ ] is equivalent to test command
# [[ ]] is enhanced version (Bash-specific)

# String comparisons
[[ "$str1" == "$str2" ]]  # Equal
[[ "$str1" != "$str2" ]]  # Not equal
[[ -z "$str" ]]           # Empty string/null
[[ -n "$str" ]]           # Not empty string

# Numeric comparisons
[[ $num1 -eq $num2 ]]     # Equal
[[ $num1 -ne $num2 ]]     # Not equal
[[ $num1 -lt $num2 ]]     # Less than
[[ $num1 -le $num2 ]]     # Less than or equal
[[ $num1 -gt $num2 ]]     # Greater than
[[ $num1 -ge $num2 ]]     # Greater than or equal

# File tests
[[ -e $file ]]            # Exists
[[ -f $file ]]            # Is a regular file
[[ -d $file ]]            # Is a directory
[[ -s $file ]]            # Size greater than zero
[[ -r $file ]]            # Readable
[[ -w $file ]]            # Writable
[[ -x $file ]]            # Executable

# Logical operators
[[ condition1 && condition2 ]]  # AND
[[ condition1 || condition2 ]]  # OR
[[ ! condition ]]               # NOT

# Case statement
case "$variable" in
    pattern1)
        commands1
        ;;
    pattern2|pattern3)
        commands2
        ;;
    *)  # Default case
        default_commands
        ;;
esac
```

## Loops

```bash
# For loop (list)
for name in John Jane Alex; do
    echo "Hello $name"
done

# For loop (range)
for i in {1..5}; do
    echo "Number $i"
done

# For loop (C-style)
for ((i=0; i<5; i++)); do
    echo "Count: $i"
done

# While loop
counter=0
while [ $counter -lt 5 ]; do
    echo "Counter: $counter"
    ((counter++))
done

# Until loop (executes until condition becomes true)
counter=0
until [ $counter -ge 5 ]; do
    echo "Counter: $counter"
    ((counter++))
done

# Break and continue
for i in {1..10}; do
    [ $i -eq 5 ] && continue  # Skip iteration when i=5
    [ $i -eq 8 ] && break     # Exit loop when i=8
    echo $i
done
```

## Functions

```bash
# Declaring functions
function greet() {
    echo "Hello, $1!"
}

# Alternate syntax
welcome() {
    local name=$1  # local variable
    echo "Welcome, $name!"
}

# Calling functions
greet "World"
welcome "John"

# Return values
get_sum() {
    local a=$1
    local b=$2
    echo $((a + b))  # return via stdout
    return 0  # return status (0-255)
}

# Capturing function output
sum=$(get_sum 5 3)
echo "Sum is $sum"
```

## Arrays

```bash
# Declaring arrays
fruits=("Apple" "Banana" "Cherry")
numbers=(1 2 3 4 5)

# Associative arrays (dictionaries, Bash 4+)
declare -A user_info
user_info[name]="John"
user_info[age]=30

# Accessing elements
echo ${fruits[0]}                # First element
echo ${fruits[-1]}               # Last element
echo ${fruits[@]}                # All elements
echo ${#fruits[@]}               # Array length
echo ${!fruits[@]}               # All indices

# Slicing arrays
echo ${fruits[@]:1:2}            # Elements 1 to 2

# Looping through arrays
for fruit in "${fruits[@]}"; do
    echo "Fruit: $fruit"
done

# Looping through associative arrays
for key in "${!user_info[@]}"; do
    echo "$key: ${user_info[$key]}"
done
```

## String Operations

```bash
string="Hello World"

# Length
echo ${#string}                  # 11

# Substring
echo ${string:6}                 # World
echo ${string:0:5}               # Hello

# Replacement
echo ${string/World/Universe}    # Hello Universe (first occurrence)
echo ${string//o/O}              # HellO WOrld (all occurrences)

# Case modification
echo ${string^}                  # Hello World (capitalize first letter)
echo ${string^^}                 # HELLO WORLD (all uppercase)
echo ${string,}                  # hello World (lowercase first letter)
echo ${string,,}                 # hello world (all lowercase)

# Strip prefix/suffix
echo ${string#He}                # llo World (remove prefix)
echo ${string##*o}               # rld (remove longest prefix match)
echo ${string%ld}                # Hello Wor (remove suffix)
echo ${string%%or*}              # Hello W (remove longest suffix match)
```

## Parameter Expansion

```bash
# Default values
echo ${var:-default}             # Use default if var is unset or null
echo ${var:=default}             # Assign default if var is unset or null
echo ${var:+alternate}           # Use alternate if var is set and not null
echo ${var:?error}               # Display error if var is unset or null

# Variable indirection
name="value"
ref="name"
echo ${!ref}                     # Prints "value"
```

## Advanced Command Execution

```bash
# Subshells
(cd /tmp && ls)                  # Current directory unchanged

# Process substitution
diff <(ls dir1) <(ls dir2)       # Compare outputs
while read line; do
    echo "Line: $line"
done < <(grep pattern file)

# Backgrounding and job control
command &                        # Run in background
wait                             # Wait for all background jobs
wait $pid                        # Wait for specific job

# Traps (signal handling)
trap "echo 'Ctrl+C pressed'; exit" SIGINT
trap "rm -f $temp_file; exit" EXIT

# Timeout
timeout 5s command               # Run with 5-second timeout
```

## Advanced I/O and Redirection

```bash
# Here documents (multiline strings)
cat << EOF > output.txt
This is line 1
This is line 2
Variables like $HOME are expanded
EOF

# Here strings (single-line input)
grep "pattern" <<< "$string"

# Process substitution
diff <(sort file1) <(sort file2)

# Redirecting specific file descriptors
command 2>&1                     # Redirect stderr to stdout
command &>/dev/null              # Redirect both stdout and stderr to /dev/null
exec 3>logfile                   # Open file descriptor 3 for writing
echo "log entry" >&3             # Write to file descriptor 3
exec 3>&-                        # Close file descriptor 3
```

## Script Options and Arguments

```bash
# Command-line arguments
echo "Script name: $0"
echo "First argument: $1"
echo "All arguments: $@"
echo "Number of arguments: $#"

# Shift arguments
shift                            # Removes $1
shift 2                          # Removes $1 and $2

# Getopts for option parsing
while getopts ":a:b:c" opt; do
    case $opt in
        a) a_arg="$OPTARG" ;;
        b) b_arg="$OPTARG" ;;
        c) c_flag=true ;;
        \?) echo "Invalid option: -$OPTARG" >&2; exit 1 ;;
        :) echo "Option -$OPTARG requires an argument" >&2; exit 1 ;;
    esac
done
shift $((OPTIND-1))              # Remove processed options
```

## Error Handling

```bash
# Exit on error
set -e                           # Exit if any command fails
set -u                           # Exit if undefined variable is used
set -o pipefail                  # Exit if any command in pipeline fails
set -x                           # Print each command before execution (debugging)

# Error handling function
handle_error() {
    local line_no=$1
    local exit_code=$2
    echo "Error on line $line_no, exit code $exit_code" >&2
    exit $exit_code
}
trap 'handle_error $LINENO $?' ERR

# Check command success
if ! command; then
    echo "Command failed" >&2
    exit 1
fi
```

## Debugging Tips

```bash
# Enable debugging mode
bash -x script.sh                # Run with debugging
set -x                           # Enable debugging
set +x                           # Disable debugging

# Debug specific sections
set -x
commands_to_debug
set +x

# Check script syntax without executing
bash -n script.sh
```

## Best Practices

1. **Always validate input**
   ```bash
   if [[ -z "$input" ]]; then
       echo "Error: Input cannot be empty" >&2
       exit 1
   fi
   ```

2. **Use meaningful variable names**
   ```bash
   # Good
   user_name="John"
   
   # Bad
   u="John"
   ```

3. **Comment your code**
   ```bash
   # Calculate age from birth year
   age=$((current_year - birth_year))
   ```

4. **Use functions for repeated tasks**
   ```bash
   check_file_exists() {
       if [[ ! -f "$1" ]]; then
           echo "Error: File $1 does not exist" >&2
           return 1
       fi
       return 0
   }
   ```

5. **Use proper exit codes**
   ```bash
   # 0: Success
   # 1-255: Various error conditions
   exit 0  # Successful execution
   exit 1  # General error
   ```

6. **Quote variables**
   ```bash
   # Good
   file_name="My Document.txt"
   rm "$file_name"
   
   # Bad (breaks with spaces)
   rm $file_name
   ```

7. **Use shellcheck for script validation**
   ```bash
   shellcheck script.sh
   ```

8. **Create temporary files safely**
   ```bash
   temp_file=$(mktemp)
   trap "rm -f $temp_file" EXIT
   ```

9. **Avoid unnecessary subshells**
   ```bash
   # Good
   count=$(wc -l < file.txt)
   
   # Less efficient
   count=$(cat file.txt | wc -l)
   ```

10. **Handle script termination**
    ```bash
    cleanup() {
        # Remove temp files, close connections, etc.
        rm -f "$temp_file"
        echo "Cleanup complete"
    }
    trap cleanup EXIT
    ```

