import { PlaybookModule } from '../types';

interface PlaybookModalProps {
  playbook: PlaybookModule | null;
  onClose: () => void;
}

export default function PlaybookModal({ playbook, onClose }: PlaybookModalProps) {
  if (!playbook) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-[#070e1d]/80 backdrop-blur-md transition-opacity"
        onClick={onClose}
      />

      {/* Modal Dialog */}
      <div className="relative w-full max-w-lg bg-[#0c1322] border border-[#232a3a] rounded-t-2xl sm:rounded-2xl p-5 shadow-2xl z-10 max-h-[85vh] overflow-y-auto space-y-4">
        <div className="w-12 h-1.5 rounded-full bg-[#232a3a] mx-auto sm:hidden mb-2" />

        {/* Header */}
        <div className="flex items-start justify-between gap-3 border-b border-[#232a3a] pb-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-[#191f2f] flex items-center justify-center text-[#4fdbc8] shadow-inner">
              <span className="material-symbols-outlined text-[24px]">{playbook.icon}</span>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className={`px-2 py-0.5 rounded-full font-mono text-[10px] uppercase font-bold ${playbook.tagColor}`}>
                  {playbook.tag}
                </span>
                <span className="text-[10px] text-[#958ea0] font-mono">SOC PLAYBOOK #0{playbook.id.replace('pb-', '')}</span>
              </div>
              <h2 className="font-headline-sm text-[18px] font-bold text-[#dce2f7] mt-1">
                {playbook.title}
              </h2>
            </div>
          </div>
          <button
            onClick={onClose}
            className="w-8 h-8 flex items-center justify-center rounded-lg bg-[#191f2f] hover:bg-[#232a3a] text-[#cbc3d7]"
          >
            <span className="material-symbols-outlined text-[18px]">close</span>
          </button>
        </div>

        {/* Content */}
        <div className="space-y-4 text-sm text-[#cbc3d7]">
          <div>
            <h3 className="text-xs uppercase font-mono font-bold text-[#958ea0] tracking-wider mb-1.5">
              Threat Overview & Mechanics
            </h3>
            <p className="leading-relaxed bg-[#141b2b] p-3 rounded-xl border border-[#232a3a]">
              {playbook.fullPlaybook.overview}
            </p>
          </div>

          <div>
            <h3 className="text-xs uppercase font-mono font-bold text-[#4fdbc8] tracking-wider mb-2 flex items-center gap-1.5">
              <span className="material-symbols-outlined text-[16px]">radar</span>
              Detection Strategies
            </h3>
            <div className="space-y-2">
              {playbook.fullPlaybook.detectionStrategy.map((strat, i) => (
                <div key={i} className="flex items-start gap-2.5 bg-[#191f2f] p-2.5 rounded-lg border border-[#232a3a]/60">
                  <span className="w-5 h-5 rounded-full bg-[#4fdbc8]/15 text-[#4fdbc8] flex items-center justify-center text-xs font-mono font-bold shrink-0">
                    {i + 1}
                  </span>
                  <p className="text-xs leading-relaxed text-[#dce2f7]">{strat}</p>
                </div>
              ))}
            </div>
          </div>

          <div>
            <h3 className="text-xs uppercase font-mono font-bold text-[#d0bcff] tracking-wider mb-2 flex items-center gap-1.5">
              <span className="material-symbols-outlined text-[16px]">security</span>
              Mitigation Steps
            </h3>
            <div className="space-y-2">
              {playbook.fullPlaybook.mitigationSteps.map((mit, i) => (
                <div key={i} className="flex items-start gap-2.5 bg-[#191f2f] p-2.5 rounded-lg border border-[#232a3a]/60">
                  <span className="material-symbols-outlined text-[#d0bcff] text-[16px] shrink-0 mt-0.5">
                    check_circle
                  </span>
                  <p className="text-xs leading-relaxed text-[#dce2f7]">{mit}</p>
                </div>
              ))}
            </div>
          </div>

          <div>
            <h3 className="text-xs uppercase font-mono font-bold text-[#ffb3ad] tracking-wider mb-1.5">
              Example Attack Payload
            </h3>
            <pre className="p-3 rounded-xl bg-[#070e1d] border border-[#232a3a] text-[#ffb3ad] font-mono text-[11px] overflow-x-auto whitespace-pre-wrap">
              {playbook.fullPlaybook.examplePayload}
            </pre>
          </div>
        </div>

        {/* Footer */}
        <div className="pt-2 border-t border-[#232a3a] flex gap-2">
          <button
            onClick={onClose}
            className="w-full py-2.5 rounded-xl bg-[#a078ff] hover:bg-[#a078ff]/90 text-[#340080] font-headline-sm text-sm font-bold shadow-lg transition-all"
          >
            Acknowledge Playbook
          </button>
        </div>
      </div>
    </div>
  );
}

