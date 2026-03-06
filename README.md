# Home Network Audit
This project served as a practical exploration into the mechanics of network communication and security auditing. By building and documenting this audit process, I gained hands-on experience with how data travels across a local network and how to identify potential entry points in a system.

## Key Learning Outcomes
Through the development of this project, I have mastered the following concepts:

1. Fundamental Networking Concepts
I gained a deep understanding of the OSI Model, specifically focusing on the Transport and Network layers. I learned how data is encapsulated and routed between devices on a local area network (LAN).

2. Client-Server Architecture
I explored the request-response cycle that governs modern computing. This project helped me visualize how a server listens for incoming connections and how clients initiate requests to specific services.

Shutterstock

3. Socket Programming & Port Logic
I learned the significance of Socket Addresses (the combination of an IP address and a port number). Understanding that a port acts as a specific "doorway" to a service was crucial in learning how to target or secure specific applications.

4. Port State Analysis
I developed the ability to distinguish between different port states, which is essential for any network audit:

Open: The application is actively accepting connections.

Closed: The port is reachable but no service is listening.

Filtered: A firewall or filter is dropping the packets, making it impossible to determine if the port is open or closed.

5. Network Exploration with Nmap
I gained proficiency in using Nmap, the industry-standard tool for network discovery. I learned how to use different scan types to map out a network, identify active hosts, and detect version information of running services.

6. Security Mindset
Beyond the technical skills, this project taught me the importance of the "Least Privilege" principle—ensuring that only necessary ports are open to minimize the attack surface of a home or enterprise network.