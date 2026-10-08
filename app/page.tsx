export default function Home() {
  return <main style={{padding:'2rem',fontFamily:'system-ui',maxWidth:720}}><h1>OpenDART 개인용 커넥터</h1><p>기업 검색, 공시, 재무제표 조회를 위한 인증된 MCP 서버입니다.</p><p>ChatGPT 플러그인에서 이 서버의 <code>/api/mcp</code> 주소를 등록하고 OAuth 인증을 선택하세요.</p><p>사전 등록된 OAuth 클라이언트 ID: <code>opendart-chatgpt</code>. 공개 클라이언트이므로 클라이언트 비밀키는 없습니다. PKCE가 필수입니다.</p><p>DART 인증키는 서버 비밀 설정에만 보관됩니다. URL이나 대화에 키를 입력할 필요가 없습니다.</p></main>;
}
