import { ChangeEventHandler } from "react";

export const GTF_PLACEHOLDER = `
GL000009.2      ENSEMBL gene    56140   58376   .       -       .       ID=ENSG00000278704.1;gene_id=ENSG00000278704.1;gene_type=protein_coding;gene_name=ENSG00000278704;level=3
GL000009.2      ENSEMBL transcript      56140   58376   .       -       .       ID=ENST00000618686.1;Parent=ENSG00000278704.1;gene_id=ENSG00000278704.1;transcript_id=ENST00000618686.1;gene_type=protein_coding;gene_name=ENSG00000278704;transcript_type=protein_coding;transcript_name=ENST00000618686;level=3;protein_id=ENSP00000484918.1;transcript_support_level=NA;tag=basic,Ensembl_canonical
GL000009.2      ENSEMBL exon    56140   58376   .       -       .       ID=exon:ENST00000618686.1:1;Parent=ENST00000618686.1;gene_id=ENSG00000278704.1;transcript_id=ENST00000618686.1;gene_type=protein_coding;gene_name=ENSG00000278704;transcript_type=protein_coding;transcript_name=ENST00000618686;exon_number=1;exon_id=ENSE00003753029.1;level=3;protein_id=ENSP00000484918.1;transcript_support_level=NA;tag=basic,Ensembl_canonical
`.trim();

export function GtfTextBox(props: {
    value: string,
    placeholder?: string,
    onChange?: ChangeEventHandler<HTMLTextAreaElement>
}) {
    return (
        <textarea
            value={props.value}
            wrap="off"
            style={{
                width: "100%",
                height: "100%",
                fontFamily: "monospace",
                fontSize: "1em",
                resize: "none"
            }}
            rows={10}
            placeholder={props.placeholder}
            readOnly={!props.onChange}
            onChange={props.onChange}
        />
    )
}