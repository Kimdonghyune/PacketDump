package test;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;

import javax.xml.bind.DatatypeConverter;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

public class localnetworkSearch extends Thread{
    //16������ �ƽ�Ű�ڵ�� ��ȯ
	private static String hexToAscii(String hexString) {
		StringBuilder output = new StringBuilder();
		//16������ ����� ���� 2���� ���ڿ� �����Ͽ� �ش� ���ڷ� �ƽ�Ű ��ȯ
		for(int i = 0; i < hexString.length(); i += 2) {
			String hexValue = hexString.substring(i, i + 2);
			int decimalValue = Integer.parseInt(hexValue, 16);
			output.append((char) decimalValue);
		}
		return output.toString();
	}
	
	@Override
	public void run() {
		//��Ʈ��ũ ��� �����ϴ� ������ �Ҵ�
    	ArrayList<PcapIf> allDevs = new ArrayList<PcapIf>();
    	//���� �޼����� ��� ����
    	StringBuilder errbuf = new StringBuilder();
    	
    	int searchPort = 25;
    	
    	//��Ʈ��ũ ��� ã�Ƽ� ����, ��Ʈ��ũ ��� ��ã���� return�Ͽ� ����
    	Pcap.findAllDevs(allDevs, errbuf);
    	if(allDevs.isEmpty()) {
    		System.out.println("��Ʈ��ũ ��ġ�� ã�� �� �����ϴ�. ���� : " + errbuf.toString());
    		return;
    	}
    	System.out.println("[ ��Ʈ��ũ ��� Ž�� ���� ]");
    	
    	//ã�� ��� �ϳ��� ���鼭 ���� ���
    	for(int i = 0; i<allDevs.size(); i++) {
    		PcapIf device = allDevs.get(i);
    		String description = (device.getDescription() != null) ? device.getDescription() : "��� ���� ������ �����ϴ�.";
    		System.out.printf("[%d��] : %s [%s]\n", i, device.getName(), description);
    	}
    	
    	//��Ʈ��ũ ��ġ �߿��� �ϳ��� ���� (0�� ���� : ���� ��Ʈ��ũ ��ġ)
    	PcapIf device = allDevs.get(0);
    	System.out.printf("���õ� ��ġ %s \n", (device.getDescription() != null) ? device.getDescription() : device.getName());
    	
    	//65536����Ʈ ��ŭ ��Ŷ ĸó
    	int snaplen = 64 * 1024;
    	
    	//����̽��� ���� ���� - �ش� ��Ʈ��ũ ��ġ�� ������ ��� ��Ŷ ĸó�ϴ� ���
    	int flags = Pcap.MODE_NON_PROMISCUOUS;
    	
    	//Ÿ�� �ƿ��� 20�ʷ� ����
    	int timeout = 20 * 1000;
    	
    	//��ġ�� ��Ŷ ĸó�� Ȱ��ȭ�մϴ� Pcap.openLive(���� ��Ʈ��ũ ��ġ, 65536����Ʈ, ����̽��� ���, Ÿ�Ӿƿ�, ���� ����);
    	Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
    	
    	//Pcap ��ü�� �������� ������ ���� �޼��� �߻�
    	if(pcap == null) {
    		System.out.println("��Ŷ ĸó�� ���� ��Ʈ��ũ ��ġ�� ���µ� ���� ����: " + errbuf.toString());
    		return;
    	}
    	
    	//IP �ּ� ��ü ����
    	Ip4 ip = new Ip4();
    	
    	//TCP �ּ� ��ü ����
    	Tcp tcp = new Tcp();
    	
    	//ĸó�� ��Ŷ�� ��� ��ü ����
    	PcapHeader header = new PcapHeader(JMemory.POINTER);
    	
    	//��Ŷ ���� ���� ����
    	JBuffer buf = new JBuffer(JMemory.POINTER);
    	
    	//PCAP�� ������ ��ũ Ÿ���� JnetPcap�� �������� ID������ ����
    	int id = JRegistry.mapDLTToId(pcap.datalink());
    	
    	//�ð� ���� ���ڿ� ���� ����
    	SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    	
    	String filePath = "C:\\data\\Local_Packet_Dump.txt";
        File file = new File(filePath); //File��ü ����
        if(!file.exists()){ //������ �������� ������
            try {
				file.createNewFile();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} //�űԻ���
        }

        // BufferedWriter ����
        BufferedWriter writer = null;
		try {
			writer = new BufferedWriter(new FileWriter(file, false));
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
        StringBuffer result = new StringBuffer();
        
    	System.out.println("��ĵ ����");
    	//������ �߻����� �ʴ� �� ����ؼ� ���� ��Ŷ�� �Է¹���
    	while(pcap.nextEx(header, buf) == Pcap.NEXT_EX_OK) {
    		PcapPacket packet = new PcapPacket(header, buf);
    		packet.scan(id);
    		
    		if(packet.hasHeader(tcp)) {
    			byte[] compare_payloadData = tcp.getPayload();//TCP�� �ִ� payload �� ������(����Ʈ ����)
    			String compare_payload = DatatypeConverter.printHexBinary(compare_payloadData);//����Ʈ���¸� ���ڿ��������� ��ȯ
    			String asciiCode = hexToAscii(compare_payload);//16������ �ƽ�Ű �ڵ�� ��ȯ
    			
        		if((tcp.source() == searchPort || tcp.destination() == searchPort) && asciiCode.length() != 0) {
        			Date date = new Date(packet.getCaptureHeader().timestampInMillis());
        			String nowTime1 = sdf1.format(date);
        			System.out.println("�ð�: " + nowTime1);
        			result.append("=============\n");
        			result.append("�ð� : " + nowTime1 + "\n");
        			
        			//��� ��Ʈ�� searchPort�̸� Jmeter���� SMEX��
        			if(tcp.source() == searchPort) {
        				System.out.println("Jmeter -> SMEX");
        				result.append("Jmeter -> SMEX\n");
        			}
        			
        			//���� ��Ʈ�� searchPort�̸� SMEX���� Jmeter��
        			if(tcp.destination() == searchPort) {
        				System.out.println("SMEX -> Jmeter");
        				result.append("SMEX -> Jmeter\n");
        			}
        			
        			//������� ������ ��Ʈ��ȣ ���
        			System.out.println("����� Port ��ȣ : " + tcp.source());
        			System.out.println("������ Port ��ȣ : " + tcp.destination());
    				result.append("����� port ��ȣ : " + tcp.source() + "\n");
    				result.append("������ port ��ȣ : " + tcp.destination() + "\n");
        			
        			//��Ŷ�� ������� IP �κи� ����(���� ��Ʈ��ũ�� �� �� �Ȱ��� 10.10.10.84�� ����)
        			if(packet.hasHeader(ip)) {
        				System.out.printf("����� IP �ּ� : %s\n������ IP �ּ� : %s\n", FormatUtils.ip(ip.source()), FormatUtils.ip(ip.destination()));	
        				result.append("����� IP �ּ� : " + FormatUtils.ip(ip.source()) + "\n");
        				result.append("������ IP �ּ� : " + FormatUtils.ip(ip.destination()) + "\n");
        			}
        			
        			//packet.hasHeader(payload); <- �ش� ��Ŷ�� ������ ��������� payload�� �ִ��� ���� �Ǵ��ϴ� �޼ҵ��̸� ������ payload�� �ش� ������� ����(payload�� ��������� �ƴ϶� ������)
        			
        			byte[] tcp_payloadData = tcp.getPayload();//TCP ��Ŷ������ payload�� ������(16���� ����)
        			String payloadData = DatatypeConverter.printHexBinary(tcp_payloadData);//16�������¸� �ϳ��� ���ڿ��� ��ȯ
        			String asciiString = hexToAscii(payloadData);//�ش� ���ڿ��� �ƽ�Ű �ڵ�� ��ȯ�����ִ� �޼ҵ� hexToAscii()
        			System.out.println("������ : " + asciiString);
        			if(tcp.getPayload() != null) {
        				result.append("������ : " + asciiString + "\n");
        			}
        			
                	try {
						writer.write(result.toString());
						writer.flush();//������ ���� �����͸� ��� ���Ϸ� ����
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}//result�� ����Ǿ� �ִ� ���� ���ۿ� ����
                    
                    result.delete(0, result.length());//result�� ����Ǿ� �ִ� ��� ���ڿ� ����
        		}
    		}
    	}
    	pcap.close();//��Ŷ ĸó ����
    	System.out.println("���� ��ĵ ����");
    	
    	//��Ŷ���� ĸó�� �������� ����
    	try {
			writer.write(result.toString());
	        writer.flush(); //������ ���� �����͸� ��� ����
	        writer.close(); //��Ʈ�� ����
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
