import { zodResolver } from "@hookform/resolvers/zod";
import { useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import {
  Controller,
  useForm,
  useWatch,
  type FieldPathByValue,
} from "react-hook-form";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Field,
  FieldError,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { paths } from "@/config/paths";
import {
  createScanInputSchema,
  useCreateScan,
} from "@/features/scans/api/create-scan";
import type { ScanCreate } from "@/features/scans/types";
import { isApiError } from "@/lib/api-client";

const EMPTY: ScanCreate = {
  source: { kind: "npm", package: "", version: "" },
  profile: "command-injection-v0.1",
};

export function CreateScanDialog({ projectId }: { projectId: string }) {
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  const form = useForm<ScanCreate>({
    resolver: zodResolver(createScanInputSchema),
    defaultValues: EMPTY,
  });
  const kind = useWatch({ control: form.control, name: "source.kind" });
  const fields: {
    name: FieldPathByValue<ScanCreate, string>;
    label: string;
    maxLength: number;
  }[] =
    kind === "npm"
      ? [
          { name: "source.package", label: "Tên npm", maxLength: 214 },
          { name: "source.version", label: "Phiên bản", maxLength: 256 },
        ]
      : [
          { name: "source.owner", label: "Owner GitHub", maxLength: 39 },
          { name: "source.repo", label: "Repo GitHub", maxLength: 100 },
          { name: "source.commit", label: "Commit", maxLength: 40 },
        ];
  const mutation = useCreateScan({
    mutationConfig: {
      meta: { handlesError: true },
      onSuccess: (scan) => {
        close();
        void navigate({
          to: paths.scan.path,
          params: { scanId: scan.scan_id },
          search: { page: 1 },
        });
      },
      onError: (error) => {
        if (!isApiError(error, 422)) return;
        for (const issue of error.validationIssues) {
          let name = issue.loc?.at(-1);
          // Backend coordinate validators currently report at the source model, not a field.
          if (issue.msg?.includes("Invalid npm package name")) name = "package";
          else if (issue.msg?.includes("exact SemVer")) name = "version";
          else if (issue.msg?.includes("Invalid GitHub owner")) name = "owner";
          else if (issue.msg?.includes("Invalid GitHub repository"))
            name = "repo";
          else if (issue.msg?.includes("GitHub commit")) name = "commit";
          const field = fields.find((field) => field.name === `source.${name}`);
          if (field)
            form.setError(
              field.name,
              { type: "server", message: issue.msg ?? "Giá trị không hợp lệ." },
              { shouldFocus: true },
            );
        }
      },
    },
  });

  function close() {
    setOpen(false);
    form.reset(EMPTY);
    mutation.reset();
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!mutation.isPending) {
          if (next) setOpen(true);
          else close();
        }
      }}
    >
      <DialogTrigger asChild>
        <Button>Tạo scan</Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <form
          noValidate
          onSubmit={form.handleSubmit((data) => {
            form.clearErrors();
            mutation.mutate({ projectId, data });
          })}
        >
          <DialogHeader>
            <DialogTitle>Tạo scan mới</DialogTitle>
            <DialogDescription>
              Quét phiên bản npm hoặc commit GitHub cố định bằng profile
              command-injection-v0.1.
            </DialogDescription>
          </DialogHeader>
          <FieldGroup className="py-6">
            <Field>
              <FieldLabel htmlFor="scan-source">Nguồn</FieldLabel>
              <Select
                value={kind}
                disabled={mutation.isPending}
                onValueChange={(value) => {
                  form.reset({
                    ...EMPTY,
                    source:
                      value === "npm"
                        ? EMPTY.source
                        : { kind: "github", owner: "", repo: "", commit: "" },
                  });
                  mutation.reset();
                }}
              >
                <SelectTrigger id="scan-source">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="npm">npm</SelectItem>
                  <SelectItem value="github">GitHub</SelectItem>
                </SelectContent>
              </Select>
            </Field>
            {fields.map(({ name, label, maxLength }) => (
              <Controller
                key={name}
                name={name}
                control={form.control}
                render={({ field, fieldState }) => (
                  <Field data-invalid={fieldState.invalid}>
                    <FieldLabel htmlFor={`scan-${name}`}>{label}</FieldLabel>
                    <Input
                      {...field}
                      id={`scan-${name}`}
                      value={field.value ?? ""}
                      maxLength={maxLength}
                      autoComplete="off"
                      disabled={mutation.isPending}
                      aria-invalid={fieldState.invalid}
                      aria-describedby={
                        fieldState.invalid ? `scan-${name}-error` : undefined
                      }
                    />
                    {fieldState.invalid && (
                      <FieldError
                        id={`scan-${name}-error`}
                        errors={[fieldState.error]}
                      />
                    )}
                  </Field>
                )}
              />
            ))}
            {mutation.error && (
              <Alert variant="destructive">
                <AlertDescription>{mutation.error.message}</AlertDescription>
              </Alert>
            )}
          </FieldGroup>
          <DialogFooter>
            <DialogClose asChild>
              <Button
                type="button"
                variant="outline"
                disabled={mutation.isPending}
              >
                Hủy
              </Button>
            </DialogClose>
            <Button type="submit" disabled={mutation.isPending}>
              {mutation.isPending ? "Đang tạo…" : "Tạo scan"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
