// トップページのトークンの発行とコピー。ビルドのときに build.rs が JavaScript にする

type TokenResponse =
  | { token: string; expires_at: string; error?: undefined }
  | { token?: undefined; error?: string };

function byId<T extends HTMLElement>(id: string): T {
  return document.getElementById(id) as T;
}

function setup(issue: HTMLButtonElement): void {
  const message = byId('token-message');
  const output = byId<HTMLTextAreaElement>('token-value');
  const copy = byId<HTMLButtonElement>('copy-token');
  let confirming = false;

  async function issueToken(): Promise<void> {
    issue.disabled = true;
    try {
      const res = await fetch('/api/auth/token', { method: 'POST' });
      const data = (await res.json()) as TokenResponse;
      if (!data.token) {
        message.textContent = 'トークンを発行できませんでした: ' + (data.error || res.status);
        return;
      }
      output.value = data.token;
      byId('token-win').hidden = false;
      const japanTime = new Date(Date.parse(data.expires_at) + 9 * 3600 * 1000);
      byId('token-status').textContent = japanTime.toISOString().slice(0, 10) + ' まで有効';
      issue.dataset.exists = 'true';
      issue.textContent = 'トークンを再作成する';
      message.textContent = '';
      output.focus();
      output.select();
    } catch (error) {
      message.textContent = '通信に失敗しました: ' + (error as Error).message;
    } finally {
      issue.disabled = false;
    }
  }

  issue.addEventListener('click', () => {
    if (issue.dataset.exists === 'true' && !confirming) {
      confirming = true;
      issue.textContent = '本当に再作成する';
      message.textContent = 'いまのトークンは使えなくなります。';
      return;
    }
    confirming = false;
    void issueToken();
  });

  copy.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(output.value);
      copy.textContent = 'コピーしました';
    } catch {
      output.select();
      copy.textContent = '選択したのでコピーしてください';
    }
  });

  // 戻るボタンなどで、トークンが画面に戻ってこないようにする
  addEventListener('pagehide', () => {
    output.value = '';
    byId('token-win').hidden = true;
  });
}

const issue = document.getElementById('issue-token');
if (issue) {
  setup(issue as HTMLButtonElement);
}
