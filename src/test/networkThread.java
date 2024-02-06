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

public class networkThread extends Thread {
	private boolean end;
	// 16������ �ƽ�Ű�ڵ�� ��ȯ
	private static String hexToAscii(String hexString) {
		StringBuilder output = new StringBuilder();
		// 16������ ����� ���� 2���� ���ڿ� �����Ͽ� �ش� ���ڷ� �ƽ�Ű ��ȯ
		for (int i = 0; i < hexString.length(); i += 2) {
			String hexValue = hexString.substring(i, i + 2);
			int decimalValue = Integer.parseInt(hexValue, 16);
			output.append((char) decimalValue);
		}
		return output.toString();
	}

	@Override
	public void run() {
		end = true;
		try {
			Thread.sleep(2000); //2�ʰ� ���� ��Ʈ��ũ ��� Ž�� �ߺ� ����
		} catch (InterruptedException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		// ��Ʈ��ũ ��� �����ϴ� ������ �Ҵ�
		ArrayList<PcapIf> allDevs = new ArrayList<PcapIf>();
		// ���� �޼����� ��� ����
		StringBuilder errbuf = new StringBuilder();

		int searchPort = 587; // ��Ʈ ��ȣ 587������ ����(���� ����)

		// ��Ʈ��ũ ��� ã�Ƽ� ����, ��Ʈ��ũ ��� ��ã���� return�Ͽ� ����
		Pcap.findAllDevs(allDevs, errbuf);
		if (allDevs.isEmpty()) {
			System.out.println("��Ʈ��ũ ��ġ�� ã�� �� �����ϴ�. ���� : " + errbuf.toString());
			return;
		}
		System.out.println("[ ��Ʈ��ũ ��� Ž�� ���� ]");

		// ã�� ��Ʈ��ũ ��� �ϳ��� ���鼭 ���� ���
		for (int i = 0; i < allDevs.size(); i++) {
			PcapIf device = allDevs.get(i);
			String description = (device.getDescription() != null) ? device.getDescription() : "��� ���� ������ �����ϴ�.";
			System.out.printf("[%d��] : %s [%s]\n", i, device.getName(), description);
		}

		// ��Ʈ��ũ ��ġ �߿��� �ϳ��� ���� (4�� ���� : �̴��� ��Ʈ��ũ ��ġ)
		PcapIf device = allDevs.get(4);
		System.out.printf("���õ� ��ġ %s \n",
				(device.getDescription() != null) ? device.getDescription() : device.getName());

		// 65536����Ʈ ��ŭ ��Ŷ ĸó
		int snaplen = 64 * 1024;

		// ����̽��� ���� ���� - �ش� ��Ʈ��ũ ��ġ�� ������ ��� ��Ŷ ĸó�ϴ� ���
		int flags = Pcap.MODE_PROMISCUOUS;

		// Ÿ�� �ƿ��� 20�ʷ� ���� (20�� ���� ��Ŷ�� ������ ������ ���� ����)
		int timeout = 20 * 1000;

		// ��ġ�� ��Ŷ ĸó�� Ȱ��ȭ�մϴ� Pcap.openLive(��Ʈ��ũ ��ġ �̸�, ��Ŷ ĸó�� ũ��, �ð�, ���� ����);
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

		// �ð� ���� ����
		SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

		String filePath = "C:\\data\\network_allPacket_Dump.txt"; // �ش� ��ġ�� �ش� ���ϸ����� ���� ����
		File file = new File(filePath); // File ��ü ����
		if (!file.exists()) { // ������ �������� ������
			try {
				file.createNewFile(); // ���� ����
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

		// �����͸� ������ ��ġ�� ���� ���� ���� ����� 2���� ����
		StringBuffer sourceResult = new StringBuffer(); // sourceResult�� �����͸� ������ ���� ������ ����
		StringBuffer destinationResult = new StringBuffer(); // destinationResult�� �����͸� ������ ���� ������ ����

		System.out.println(searchPort + "��Ʈ ��Ʈ��ũ ��ĵ ����");
		// ������ �߻����� �ʴ� �� ����ؼ� ���� ��Ŷ�� �Է¹���, end���� �̿��Ͽ� ���ѷ��� Ż��(��Ʈ��ũ ��ġ�� ��� �ٸ� ���ͳ� ��Ŷ�� ���� timeout���� ���ᰡ �ȵ�)
		while (pcap.nextEx(header, buf) == Pcap.NEXT_EX_OK && end) {
			PcapPacket packet = new PcapPacket(header, buf); //��Ŷ ����� ��Ŷ �����ͷ� packet ����
			packet.scan(id); // scan �޼���� ��Ŷ�� ���� �����͸� �а� �м��Ͽ� ���������� Ư�� �ʵ峪 Ư¡�� �ĺ�
			// TCP(��Ʈ��ȣ)�� 587�̸� SMTP
			if (packet.hasHeader(tcp)) {
				byte[] compare_payloadData = tcp.getPayload(); // TCP�� �ִ� payload �� ������(����Ʈ ����)
				String compare_payload = DatatypeConverter.printHexBinary(compare_payloadData); // ����Ʈ���¸� ���ڿ��������� ��ȯ
				String asciiCode = hexToAscii(compare_payload); // 16������ �ƽ�Ű �ڵ�� ��ȯ

				if ((tcp.source() == searchPort || tcp.destination() == searchPort) && asciiCode.length() != 0) {
					Date date = new Date(packet.getCaptureHeader().timestampInMillis()); // ��Ŷ ������� �ð��� �ʴ����� ������
					String nowTime = sdf1.format(date); // �� ������ ��¥ ���Ŀ� ���� ���ڿ��� ����

					// packet.hasHeader(payload) ->�� ����� packet�� ����������� payload�� �ִ��� ���θ� Ȯ���ϴ� �޼ҵ��
					// ���� payload�� ������(tcp�� payload���� �����;���)

					byte[] tcp_payloadData = tcp.getPayload();// TCP�� �ִ� payload �� ������(����Ʈ ����)
					String payloadData = DatatypeConverter.printHexBinary(tcp_payloadData);// ����Ʈ���¸� ���ڿ��������� ��ȯ
					String asciiString = hexToAscii(payloadData);// 16������ �ƽ�Ű �ڵ�� ��ȯ
					
					packet.hasHeader(ip); // ��Ŷ ��� �������� ip ������ ������
					if(tcp.source() == searchPort) {
						if(sourceResult.length() == 0) {
							sourceResult.append("============ \n" + "�ð� : " + nowTime + "\n" + "SMEX -> SMTP \n"
									+ "����� IP �ּ� : " + FormatUtils.ip(ip.source()) + "\n" + "������ IP �ּ� : " + FormatUtils.ip(ip.destination()) + "\n"
									+ "����� Port �ּ� : " + tcp.source() + "\n" + "������ Port �ּ� :" + tcp.destination() + "\n" + "������ : \n"
									);							
						}
						else {
							sourceResult.append(asciiString); // ������ �߰�
						}
					}
					
					if(tcp.destination() == searchPort) {
						if(destinationResult.length() == 0) {
							destinationResult.append("\n============ \n" + "�ð� : " + nowTime + "\n" + "SMEX -> SMTP \n"
									+ "����� IP �ּ� : " + FormatUtils.ip(ip.source()) + "\n" + "������ IP �ּ� : " + FormatUtils.ip(ip.destination()) + "\n"
									+ "����� Port �ּ� : " + tcp.source() + "\n" + "������ Port �ּ� :" + tcp.destination() + "\n" + "������ : \n"
									);							
						}
						else {
							destinationResult.append(asciiString); // ������ �߰�
						}
					}
				}
			}
		}
		
		if(pcap != null) { //timeout�� �Ǿ��� �� �̹� pacp�� ������ ������ �� �ݴ°��� ����
			pcap.close();
		}
		
		try {
			writer.write(sourceResult.toString());
			writer.flush();
			writer.write(destinationResult.toString());
			writer.flush();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		System.out.println(searchPort + "��Ʈ ��Ʈ��ũ ��ĵ ����");
		System.out.println(sourceResult.toString());
		System.out.println(destinationResult.toString());
	}
	
	void stopThread() {
		end = false;
	}
}
