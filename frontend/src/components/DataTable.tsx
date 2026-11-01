import { useState } from "react";
import type { ReactNode } from "react";
import { flexRender, getCoreRowModel, getPaginationRowModel, getSortedRowModel, useReactTable } from "@tanstack/react-table";
import type { ColumnDef, SortingState } from "@tanstack/react-table";
import { ArrowDown, ArrowUp, ChevronLeft, ChevronRight } from "lucide-react";
import { Empty } from "./ui";

export function DataTable<T>({ data, columns, onRow, selected, pageSize = 50, empty = "No rows match", initialSort, extra }: {
  data: T[]; columns: ColumnDef<T, any>[]; onRow?: (r: T) => void; selected?: (r: T) => boolean; pageSize?: number; empty?: string; initialSort?: SortingState; extra?: ReactNode;
}) {
  const [sorting, setSorting] = useState<SortingState>(initialSort ?? []);
  const t = useReactTable({ data, columns, state: { sorting }, onSortingChange: setSorting, getCoreRowModel: getCoreRowModel(), getSortedRowModel: getSortedRowModel(), getPaginationRowModel: getPaginationRowModel(), initialState: { pagination: { pageSize } }, autoResetPageIndex: true });
  if (!data.length) return <Empty title={empty} />;
  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="flex-1 min-h-0 overflow-auto">
        <table className="tbl">
          <thead>{t.getHeaderGroups().map((g) => <tr key={g.id}>{g.headers.map((h) => (
            <th key={h.id} onClick={h.column.getToggleSortingHandler()} className={h.column.getCanSort() ? "cursor-pointer hover:text-sub" : ""}>
              <span className="inline-flex items-center gap-1">{flexRender(h.column.columnDef.header, h.getContext())}
                {h.column.getIsSorted() === "asc" && <ArrowUp size={10} />}{h.column.getIsSorted() === "desc" && <ArrowDown size={10} />}</span>
            </th>))}</tr>)}</thead>
          <tbody>{t.getRowModel().rows.map((r) => (
            <tr key={r.id} className={`${onRow ? "click" : ""} ${selected?.(r.original) ? "sel" : ""}`} onClick={() => onRow?.(r.original)}>
              {r.getVisibleCells().map((c) => <td key={c.id}>{flexRender(c.column.columnDef.cell, c.getContext())}</td>)}
            </tr>))}</tbody>
        </table>
      </div>
      {(t.getPageCount() > 1 || extra) && (
        <div className="flex items-center gap-2 h-8 px-3 border-t border-line2 text-2xs text-mute shrink-0">
          {extra}<span className="flex-1" />
          {t.getPageCount() > 1 && <>
            <span>{data.length.toLocaleString("en-US")} rows · page {t.getState().pagination.pageIndex + 1}/{t.getPageCount()}</span>
            <button aria-label="Previous page" className="btn btn-ghost !h-6 !px-1" disabled={!t.getCanPreviousPage()} onClick={() => t.previousPage()}><ChevronLeft size={12} /></button>
            <button aria-label="Next page" className="btn btn-ghost !h-6 !px-1" disabled={!t.getCanNextPage()} onClick={() => t.nextPage()}><ChevronRight size={12} /></button>
          </>}
        </div>
      )}
    </div>
  );
}
