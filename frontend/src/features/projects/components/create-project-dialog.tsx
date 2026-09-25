import { zodResolver } from "@hookform/resolvers/zod";
import { useNavigate } from "@tanstack/react-router";
import { Loader2Icon, PlusIcon } from "lucide-react";
import { useState, type ReactNode } from "react";
import { Controller, useForm, useWatch } from "react-hook-form";
import { toast } from "sonner";
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
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { paths } from "@/config/paths";
import {
  createProjectInputSchema,
  useCreateProject,
  type CreateProjectInput,
} from "@/features/projects/api/create-project";
import {
  PROJECT_DESCRIPTION_MAX,
  PROJECT_NAME_MAX,
} from "@/features/projects/types";

const EMPTY: CreateProjectInput = { name: "", description: "" };

export function CreateProjectDialog({
  trigger,
}: {
  /** Custom trigger element; defaults to a "Tạo dự án" button. */
  trigger?: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  const form = useForm<CreateProjectInput>({
    resolver: zodResolver(createProjectInputSchema),
    defaultValues: EMPTY,
  });
  const description = useWatch({ control: form.control, name: "description" });
  const createProject = useCreateProject({
    mutationConfig: {
      // The error is rendered inside the dialog, not as a global toast.
      meta: { handlesError: true },
      onSuccess: (project) => {
        toast.success(`Đã tạo dự án “${project.name}”.`);
        close();
        void navigate({
          to: paths.project.path,
          params: { projectId: project.id },
        });
      },
    },
  });

  function close() {
    setOpen(false);
    form.reset(EMPTY);
    createProject.reset();
  }

  function onOpenChange(next: boolean) {
    if (createProject.isPending) return;
    if (next) setOpen(true);
    else close();
  }

  const onSubmit = form.handleSubmit((values) => createProject.mutate(values));

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogTrigger asChild>
        {trigger ?? (
          <Button>
            <PlusIcon data-icon="inline-start" />
            Tạo dự án
          </Button>
        )}
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <form onSubmit={onSubmit} noValidate>
          <DialogHeader>
            <DialogTitle>Tạo dự án mới</DialogTitle>
            <DialogDescription>
              Dự án gom các bản mã nguồn, lượt quét và cảnh báo cần thẩm định.
            </DialogDescription>
          </DialogHeader>
          <FieldGroup className="py-6">
            <Controller
              name="name"
              control={form.control}
              render={({ field, fieldState }) => (
                <Field data-invalid={fieldState.invalid}>
                  <FieldLabel htmlFor="project-name">Tên dự án</FieldLabel>
                  <Input
                    {...field}
                    id="project-name"
                    autoFocus
                    autoComplete="off"
                    maxLength={PROJECT_NAME_MAX}
                    placeholder="Ví dụ: Python command injection"
                    aria-invalid={fieldState.invalid}
                  />
                  {fieldState.invalid && (
                    <FieldError errors={[fieldState.error]} />
                  )}
                </Field>
              )}
            />
            <Controller
              name="description"
              control={form.control}
              render={({ field, fieldState }) => (
                <Field data-invalid={fieldState.invalid}>
                  <FieldLabel htmlFor="project-description">
                    Mô tả{" "}
                    <span className="font-normal text-muted-foreground">
                      (tùy chọn)
                    </span>
                  </FieldLabel>
                  <Textarea
                    {...field}
                    id="project-description"
                    rows={4}
                    maxLength={PROJECT_DESCRIPTION_MAX}
                    placeholder="Phạm vi mã nguồn và mục tiêu đánh giá…"
                    aria-invalid={fieldState.invalid}
                  />
                  <FieldDescription className="text-right tabular-nums">
                    {description.length}/{PROJECT_DESCRIPTION_MAX}
                  </FieldDescription>
                  {fieldState.invalid && (
                    <FieldError errors={[fieldState.error]} />
                  )}
                </Field>
              )}
            />
            {createProject.error && (
              <Alert variant="destructive">
                <AlertDescription>
                  {createProject.error.message}
                </AlertDescription>
              </Alert>
            )}
          </FieldGroup>
          <DialogFooter>
            <DialogClose asChild>
              <Button
                type="button"
                variant="outline"
                disabled={createProject.isPending}
              >
                Hủy
              </Button>
            </DialogClose>
            <Button type="submit" disabled={createProject.isPending}>
              {createProject.isPending && (
                <Loader2Icon
                  data-icon="inline-start"
                  className="animate-spin"
                />
              )}
              Tạo dự án
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
