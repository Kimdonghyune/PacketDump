package test;

public class testThread {

	public static void main(String[] args) throws InterruptedException {
		localThread lt = new localThread();
		networkThread nt = new networkThread();
		lt.start();
		nt.start();
		
		if(lt != null) {
			lt.join(); // ���� ��Ʈ��ũ ��Ŷ ĸó�� timeout�� ������ ���
		}
		
		if(nt != null) {
			nt.stopThread(); // �ش� ��Ʈ��ũ ��Ŷ ĸó ����
		}
	}

}


