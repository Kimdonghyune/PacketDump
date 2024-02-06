package test;

public class testThread {

	public static void main(String[] args) throws InterruptedException {
		localThread lt = new localThread();
		networkThread nt = new networkThread();
		lt.start();
		nt.start();
		
		if(lt != null) {
			lt.join(); // 로컬 네트워크 패킷 캡처가 timeout될 때까지 대기
		}
		
		if(nt != null) {
			nt.stopThread(); // 해당 네트워크 패킷 캡처 종료
		}
	}

}


