# Azure Honeynet

Below you will see a diagram of the flow of information across the network. I opened up Azure resources for direct communication from the internet. I collected the Windows event log and the Linux logs and logs on SQL, Entra ID, my key vault, activity log, and blob storage. I then fed them into my LAW and then I filtered that through custom KQL alerts which reported the happenings inside mocrosoft sentinel. I also uploaded a spreadsheet of the geo-coordinates of the world's cities and my threat intelligence workbooks reported geolocations of the attacks. Detailed in the rest of this report is the construction of the honeynet.

![Untitled1](https://github.com/jsom98/Pictures/blob/main/Bad%20Actor%20Diagram.drawio%20(1).png)

First navigate to portal.azure.com

![Azure%20Honeynet%20936b79dcde644c74ae5e9277e9de63b7/image1.png](https://github.com/jsom98/Pictures/blob/main/image1%20(1).png)

Type "Virtual Machine" in the search bar and click on the appropriate result shown.

![Azure%20Honeynet%20936b79dcde644c74ae5e9277e9de63b7/image2.png](https://github.com/jsom98/Pictures/blob/main/image2%20(1).png)

Then click create > Azure virtual machine

![Azure%20Honeynet%20936b79dcde644c74ae5e9277e9de63b7/image3.png](https://github.com/jsom98/Pictures/blob/main/Image3.png)

Under Project Details select "create new" under Resource Group.

![Azure%20Honeynet%20936b79dcde644c74ae5e9277e9de63b7/image4.png](https://github.com/jsom98/Pictures/blob/main/Image4.png)

Then fill out the Virtual Machine Name, Region, and Image

![Azure%20Honeynet%20936b79dcde644c74ae5e9277e9de63b7/image5.png](https://github.com/jsom98/Pictures/blob/main/Image5.png)

After that choose an appropriate size and create the credentials for the admin account you will use to log into windows

![Azure%20Honeynet%20936b79dcde644c74ae5e9277e9de63b7/image6.png](https://github.com/jsom98/Pictures/blob/main/Image6.png)

Under the Networking tab select the correct Virtual Network and select Delete public IP and NIC when VM is deleted. Then click review and create

![Azure%20Honeynet%20936b79dcde644c74ae5e9277e9de63b7/image7.png](https://github.com/jsom98/Pictures/blob/main/Image7.png)

The first step was to make my VMs using Azure.

![Azure%20Honeynet%20936b79dcde644c74ae5e9277e9de63b7/image8.png](https://github.com/jsom98/Pictures/blob/main/Image8.png)

![Azure%20Honeynet%20936b79dcde644c74ae5e9277e9de63b7/image9.png](https://github.com/jsom98/Pictures/blob/main/image9.png)

I then added a firewall rule to make my virtual machines open to all ports and protocols in the Network security groups

![Azure%20Honeynet%20936b79dcde644c74ae5e9277e9de63b7/image10.png](https://github.com/jsom98/Pictures/blob/main/image10.png)

![Azure%20Honeynet%20936b79dcde644c74ae5e9277e9de63b7/image11.png](https://github.com/jsom98/Pictures/blob/main/image11.png)

I then used Remote Desktop Connection (RDC) to log into my VM using the public IP address and turned off all the firewalls to make it easier to see people trying to break into my honeynet

![Azure%20Honeynet%20936b79dcde644c74ae5e9277e9de63b7/image12.png](https://github.com/jsom98/Pictures/blob/main/image12.png)

I then edited the Windows Registry to add a network service user and edited the access to give full access to the event logs (HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Security)

![Azure%20Honeynet%20936b79dcde644c74ae5e9277e9de63b7/image13.png](https://github.com/jsom98/Pictures/blob/main/Screenshot%202024-02-18%20165756.png)

![Azure%20Honeynet%20936b79dcde644c74ae5e9277e9de63b7/image14.png](https://github.com/jsom98/Pictures/blob/main/Screenshot%202024-02-18%20165812.png)

After that I made the Data Collection Rules for my VMs

![Azure%20Honeynet%20936b79dcde644c74ae5e9277e9de63b7/image15.png](https://github.com/jsom98/Pictures/blob/main/image15.png)

Then I made the Log Analytics Workspace for my VMs

![Azure%20Honeynet%20936b79dcde644c74ae5e9277e9de63b7/image16.png](https://github.com/jsom98/Pictures/blob/main/image16.png)

![Azure%20Honeynet%20936b79dcde644c74ae5e9277e9de63b7/image17.png](https://github.com/jsom98/Pictures/blob/main/image17.png)

![Azure%20Honeynet%20936b79dcde644c74ae5e9277e9de63b7/image18.png](https://github.com/jsom98/Pictures/blob/main/image18.png)

![Azure%20Honeynet%20936b79dcde644c74ae5e9277e9de63b7/image19.png](https://github.com/jsom98/Pictures/blob/main/image19.png)
