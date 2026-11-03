"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";
import { type FieldValues, type Path, useForm } from "react-hook-form";
import type { z } from "zod";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { type Me, errorMessage } from "@/lib/api";
import { orgPath } from "@/lib/nav";
import { safeNext } from "@/lib/safe-next";
import { ME_QUERY_KEY } from "@/lib/use-me";

export type FieldSpec<T> = {
  name: Path<T>;
  label: string;
  type?: string;
  autoComplete?: string;
};

type Props<T extends FieldValues> = {
  title: string;
  description: string;
  schema: z.ZodType<T, T>;
  fields: FieldSpec<T>[];
  submitLabel: string;
  submit: (values: T) => Promise<Me>;
  footer: { text: string; href: string; link: string };
};

export function AuthForm<T extends FieldValues>(props: Props<T>) {
  const router = useRouter();
  const params = useSearchParams();
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const form = useForm<T>({ resolver: zodResolver(props.schema) });

  const onSubmit = form.handleSubmit(async (values) => {
    setError(null);
    try {
      const me = await props.submit(values);
      queryClient.clear(); // nothing cached for a previous user survives a new sign-in
      queryClient.setQueryData(ME_QUERY_KEY, me);
      const first = me.memberships.at(0);
      router.replace(safeNext(params.get("next"), first ? orgPath(first.organization_id) : "/"));
    } catch (err) {
      setError(errorMessage(err));
    }
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>{props.title}</CardTitle>
        <CardDescription>{props.description}</CardDescription>
      </CardHeader>
      <CardContent>
        <form className="flex flex-col gap-4" onSubmit={onSubmit} noValidate>
          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          {props.fields.map((field) => {
            const fieldError = form.formState.errors[field.name]?.message;
            return (
              <div key={field.name} className="flex flex-col gap-2">
                <Label htmlFor={field.name}>{field.label}</Label>
                <Input
                  id={field.name}
                  type={field.type ?? "text"}
                  autoComplete={field.autoComplete}
                  aria-invalid={Boolean(fieldError)}
                  {...form.register(field.name)}
                />
                {typeof fieldError === "string" && (
                  <p className="text-sm text-destructive">{fieldError}</p>
                )}
              </div>
            );
          })}
          <Button type="submit" disabled={form.formState.isSubmitting}>
            {form.formState.isSubmitting ? "Please wait…" : props.submitLabel}
          </Button>
          <p className="text-center text-sm text-muted-foreground">
            {props.footer.text}{" "}
            <Link className="text-foreground underline underline-offset-4" href={props.footer.href}>
              {props.footer.link}
            </Link>
          </p>
        </form>
      </CardContent>
    </Card>
  );
}
