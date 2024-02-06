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

public class localThread extends Thread {
	
	// 16������ �ƽ�Ű�ڵ�� ��ȯ
	private String hexToAscii(String hexString) {
		StringBuilder output = new StringBuilder();
		// 16������ ����� ���� 2���� ���ڿ� �����Ͽ� �ش� ���ڷ� �ƽ�Ű ��ȯ
		for (int i = 0; i < hexString.length(); i += 2) {
			String hexValue = hexString.substring(i, i + 2);
			int decimalValue = Integer.parseInt(hexValue, 16);
			output.append((char) decimalValue);
		}
		return output.toString();
	}

	public void run() {
		// ��Ʈ��ũ ��� �����ϴ� ������ �Ҵ�
		ArrayList<PcapIf> allDevs = new ArrayList<PcapIf>();
		// ���� �޼����� ��� ����
		StringBuilder errbuf = new StringBuilder();

		int searchPort = 25; //��Ʈ ��ȣ 25������ ����(���ͼ���)

		// ��Ʈ��ũ ��� ã�Ƽ� ����, ��Ʈ��ũ ��� ��ã���� return�Ͽ� ����
		Pcap.findAllDevs(allDevs, errbuf);
		if (allDevs.isEmpty()) {
			System.out.println("��Ʈ��ũ ��ġ�� ã�� �� �����ϴ�. ���� : " + errbuf.toString());
			return;
		}
		System.out.println("[ ��Ʈ��ũ ��� Ž�� ���� ]");

		// ã�� ��� �ϳ��� ���鼭 ���� ���
		for (int i = 0; i < allDevs.size(); i++) {
			PcapIf device = allDevs.get(i);
			String description = (device.getDescription() != null) ? device.getDescription() : "��� ���� ������ �����ϴ�.";
			System.out.printf("[%d��] : %s [%s]\n", i, device.getName(), description);
		}

		// ��Ʈ��ũ ��ġ �߿��� �ϳ��� ���� (0�� ���� : ���� ��Ʈ��ũ ��ġ)
		PcapIf device = allDevs.get(0);
		System.out.printf("���õ� ��ġ %s \n",
				(device.getDescription() != null) ? device.getDescription() : device.getName());

		// 65536����Ʈ ��ŭ ��Ŷ ĸó
		int snaplen = 64 * 1024;

		// ����̽��� ���� ���� - �ش� ��Ʈ��ũ ��ġ�� ������ ��� ��Ŷ ĸó�ϴ� ���
		int flags = Pcap.MODE_PROMISCUOUS;

		// Ÿ�� �ƿ��� 20�ʷ� ���� (��Ŷ�� 20�ʵ��� ������ �ʴ´ٸ� ���� ���� )
		int timeout = 20 * 1000;

		// ��ġ�� ��Ŷ ĸó�� Ȱ��ȭ�մϴ� Pcap.openLive(���� ��Ʈ��ũ ��ġ, 65536����Ʈ, ����̽��� ���, Ÿ�Ӿƿ�, ���� ����);
		Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

		// Pcap ��ü�� �������� ������ ���� �޼��� �߻�
		if (pcap == null) {
			System.out.println("��Ŷ ĸó�� ���� ��Ʈ��ũ ��ġ�� ���µ� ���� ����: " + errbuf.toString());
			return;
		}

		// IP �ּ� ��ü ����
		Ip4 ip = new Ip4();

		// TCP �ּ� ��ü ����
		Tcp tcp = new Tcp();

		// ĸó�� ��Ŷ�� ��� ��ü ����
		// JMemory.POINTER�� �����ϰ� �Ǵµ� �̴� ����� �޸��� Ư�� ��ġ�� �Ҵ��ϴ� �� ���Ǵ� JNA(Java Native Access) ���̺귯���� Pointer�� ��Ÿ��
		// ��Ŷ ����� �޸��� Ư�� ��ġ�� �Ҵ��Ͽ� ���
		PcapHeader header = new PcapHeader(JMemory.POINTER);

		// ��Ŷ ���� ���� ����
		// ��Ŷ ���� ���۸� �޸��� Ư�� ��ġ�� �Ҵ��Ͽ� ���
		JBuffer buf = new JBuffer(JMemory.POINTER);

		// PCAP�� ������ ��ũ Ÿ���� JnetPcap�� �������� ID������ ����
		int id = JRegistry.mapDLTToId(pcap.datalink());

		// �ð� ���� ���ڿ� ���� ����
		SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

		String filePath = "C:\\data\\Local_AllPacket_Dump.txt";// �ش� ���� ��ġ�� �ؽ�Ʈ ���� ����
		File file = new File(filePath); // File ��ü ����
		if (!file.exists()) { // ������ �������� ������ ���� ����
			try {
				file.createNewFile();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		// BufferedWriter ����
		BufferedWriter writer = null;
		try {
			writer = new BufferedWriter(new FileWriter(file, false)); // �ش� ������ ������ ���� ���� ���� ����� ���� ����
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		System.out.println(searchPort + "��Ʈ ���� ��ĵ ����");
		
		// �����͸� ������ ��ġ�� �������� ���� 2���� ����� ����
		StringBuffer sourceResult = new StringBuffer(); // sourceResult�� �����͸� ������ �ش� ������ ����
		StringBuffer destinationResult = new StringBuffer(); // destinationResult�� �����͸� ������ �ش� �������� ����

		// ������ �߻����� �ʴ� �� ����ؼ� ���� ��Ŷ�� �Է¹���
		while ( pcap.nextEx(header, buf) == Pcap.NEXT_EX_OK) {
			PcapPacket packet = new PcapPacket(header, buf); // ������ ��Ŷ ����� �����ͷ� packet ��ü ����
			packet.scan(id); // scan �޼���� ��Ŷ�� ���� �����͸� �а� �м��Ͽ� ���������� Ư�� �ʵ峪 Ư¡�� �ĺ�.

			if (packet.hasHeader(tcp)) {
				if (tcp.source() == searchPort || tcp.destination() == searchPort) {
					Date date = new Date(packet.getCaptureHeader().timestampInMillis()); // ��Ŷ�� �ð� ������ �ʴ����� ������
					String nowTime = sdf1.format(date); // �� ������ ��¥ ���Ŀ� ���� ���ڿ��� ��ȯ

					byte[] tcp_payloadData = tcp.getPayload();// TCP ��Ŷ������ payload�� ������ (����Ʈ ����)
					String payloadData = DatatypeConverter.printHexBinary(tcp_payloadData);// 16�������¸� �ϳ��� ���ڿ��� ��ȯ
					String asciiString = hexToAscii(payloadData);// �ش� ���ڿ��� �ƽ�Ű �ڵ�� ��ȯ�����ִ� �޼ҵ� hexToAscii()

					packet.hasHeader(ip);

					// ��� ��Ʈ�� searchPort�̸� Jmeter���� SMEX�� ȭ��ǥ ǥ��(Jmeter�� searchPort�̱� ����)
					if (tcp.source() == searchPort) {
						if (sourceResult.length() == 0) {
							sourceResult.append("============ \n" + "�ð� : " + nowTime + "\n" + "Jmeter -> SMEX\n"
									+ "����� IP �ּ� : " + FormatUtils.ip(ip.source()) + "\n" + "������ IP �ּ� : "
									+ FormatUtils.ip(ip.destination()) + "\n" + "����� Port �ּ� : " + tcp.source() + "\n"
									+ "������ Port �ּ� : " + tcp.destination() + "\n" + "������ : \n");
						} else {
							sourceResult.append(asciiString);
						}
					}

					// ���� ��Ʈ�� searchPort�̸� SMEX���� Jmeter�� ȭ��ǥ ǥ��(Jmeter�� searchPort�̱� ����)
					if (tcp.destination() == searchPort) {
						if (destinationResult.length() == 0) {
							destinationResult.append("============ \n" + "�ð� : " + nowTime + "\n" + "SMEX -> Jmeter\n"
									+ "����� IP �ּ� : " + FormatUtils.ip(ip.source()) + "\n" + "������ IP �ּ� : "
									+ FormatUtils.ip(ip.destination()) + "\n" + "����� Port �ּ� : " + tcp.source() + "\n"
									+ "������ Port �ּ� : " + tcp.destination() + "\n" + "������ : \n");
						} else {
							destinationResult.append(asciiString);
						}
					}
				}
			}
		}
		
		if(pcap != null) { // timeout�� �Ǿ������� �̹� pcap�� ���� �־ �� pcap�� �ݴ� ���� ����
			pcap.close();
		}
		
		System.out.println(searchPort + "��Ʈ ���� ��ĵ ����");
		System.out.println(sourceResult.toString());
		System.out.println(destinationResult.toString());
		try {
			writer.write(sourceResult.toString());
			writer.flush();
			writer.write(destinationResult.toString());
			writer.flush();
			writer.close(); 
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
}
