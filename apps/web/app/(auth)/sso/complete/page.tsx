export default function SsoCompletePage() {
  // M11 route shell (phase 10: the SSO callback lands here with `#next=`).
  return (
    <div className="flex flex-col gap-2 text-center">
      <h1 className="text-xl font-semibold">Signing you in</h1>
      <p className="text-sm text-muted-foreground">Single sign-on is not available yet.</p>
    </div>
  );
}
