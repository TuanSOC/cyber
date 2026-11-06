"use client";

import { z } from "zod";

import { AuthForm } from "@/components/auth/auth-form";
import { ApiError, api, isMfaChallenge, unwrap } from "@/lib/api";

const schema = z.object({
  email: z.email("Enter a valid email"),
  password: z.string().min(1, "Enter your password").max(128),
});

export default function LoginPage() {
  return (
    <AuthForm
      title="Sign in"
      description="Access your organization's investigations."
      schema={schema}
      fields={[
        { name: "email", label: "Email", type: "email", autoComplete: "email" },
        { name: "password", label: "Password", type: "password", autoComplete: "current-password" },
      ]}
      submitLabel="Sign in"
      submit={async (body) => {
        const result = unwrap(await api.POST("/api/v1/auth/login", { body }));
        // M11: the 202 MFA challenge is phase 10's (no factor can be enrolled before phase 5).
        if (isMfaChallenge(result)) {
          throw new ApiError(202, "mfa_required", "Two-factor authentication is required.");
        }
        return result;
      }}
      footer={{ text: "No account yet?", href: "/register", link: "Create one" }}
    />
  );
}
