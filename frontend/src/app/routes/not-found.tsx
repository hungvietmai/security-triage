import { Link } from "@tanstack/react-router";
import { CompassIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { paths } from "@/config/paths";
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty";

export function NotFoundRoute() {
  return (
    <Empty className="flex-none border border-dashed py-12">
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <CompassIcon />
        </EmptyMedia>
        <EmptyTitle>Không tìm thấy trang</EmptyTitle>
        <EmptyDescription>
          Đường dẫn này không tồn tại trong ứng dụng.
        </EmptyDescription>
      </EmptyHeader>
      <EmptyContent>
        <Button asChild>
          <Link to={paths.dashboard.path}>Về trang tổng quan</Link>
        </Button>
      </EmptyContent>
    </Empty>
  );
}
