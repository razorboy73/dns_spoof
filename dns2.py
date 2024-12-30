import netfilterqueue
import subprocess

def main():

    #enable forwarding to build a queue

    def add_iptables_rule():
        """
        Add an iptables rule to forward packets to NFQUEUE with queue number 0.
        """
        # Corrected the command by using the correct double dash `--`
        command = ["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"]
        
        try:
            # Execute the iptables command
            subprocess.run(command, check=True)
            print("[INFO] iptables rule added successfully.")
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to add iptables rule: {e}")
        except FileNotFoundError:
            print("[ERROR] iptables command not found. Ensure iptables is installed and in your PATH.")

    def process_packet(packet):
        print(packet)
        packet.accept()  # Continue processing the packet

    # Add the iptables rule before starting the queue
    add_iptables_rule()

    #build a queue
    queue = netfilterqueue.NetfilterQueue()
    #binds to the queue we created with iptables.  The queue number here must match the queue number in iptables
    queue.bind(0, process_packet)

    try:
        print("[INFO] Starting packet processing...")
        queue.run()
    except KeyboardInterrupt:
        print("\n[INFO] Stopping packet processing.")
    finally:
        # Remove the iptables rule when exiting
        subprocess.run(["iptables", "-D", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])
        print("[INFO] iptables rule removed.")
        
        
    
if __name__ == "__main__":
    main()

