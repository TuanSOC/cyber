"use client";

import { z } from "zod";

import { AuthForm } from "@/components/auth/auth-form";
import { api, unwrap } from "@/lib/api";

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
      submit={async (body) => unwrap(await api.POST("/api/v1/auth/login", { body }))}
      footer={{ text: "No account yet?", href: "/register", link: "Create one" }}
    />
  );
}
