#!/usr/bin/env python3
"""
Comprehensive Validation TAG-2: All 11 Topics × 3 Age Bands (33 validations)
============================================================================

Post Micro-Patch v2.3.3 - Complete validation with REAL adapted answers

Validator: v2.3.3 (anchor-overlap requirement)
Gates: v0.4.1 (no gate weakening)
NSMF: v1.3.3 (Transgender, Earth Age) / v1.3.2 (others)

Author: I0C035E (Eleventh Instance)
Date: 2025-11-03 (TAG-2 Full Batch Run)
"""

import sys
import yaml
import json
from pathlib import Path
from datetime import datetime

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src_hexagonal.services.truth_preservation_validator_v2_3 import TruthPreservationValidatorV2_3


def load_yaml(path: str):
    """Load YAML config"""
    with open(path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)


# REAL adapted answers from IC32A08 tests
# Extracted from:
# - validate_all_8_topics_multi_band_v2_3_2.py
# - validate_remaining_6_topics_v2_3.py
# - validate_evolution_drugs_multi_band_v2_3_2.py
# - validate_right_wing_extremism_v2_3_2.py

REAL_ANSWERS = {
    # Evolution
    ('evolution', '6-8'): "Humans are part of the big animal family. Long ago, all animals had very old great-great-grandparents in common. Small changes over many generations add up.",
    ('evolution', '9-12'): "Humans and other primates share ancient ancestors. Evolution means small changes add up over many generations. Scientists use genetics and fossils to study these changes. The story of modern humans began in Africa, and people later spread across the world.",
    ('evolution', '13-15'): "Humans are primates and share common ancestry with other primates. Modern humans evolved in Africa. Heritable variation and natural selection drive evolutionary change. Genetics and fossils provide convergent evidence for human evolution.",
    
    # Homosexuality
    ('homosexuality', '6-8'): "Some people love someone of the same gender. All kinds of families deserve kindness. Love comes in different forms.",
    ('homosexuality', '9-12'): "Homosexuality means romantic attraction to someone of the same sex. Major medical organizations state it is not an illness. It is a natural variation in human sexuality. Laws and social views differ by country and community.",
    ('homosexuality', '13-15'): "Major medical and psychological organizations agree that being gay is a normal variation of human sexuality, not a disease or disorder. Human rights frameworks affirm equal dignity for all people, regardless of sexual orientation. Discrimination, bullying, or violence are never acceptable. Laws and policies differ by country or region, so learn your local rules and protections. Respect, safety, and consent are essential in any relationship. If you need support or have questions, talk with a trusted adult or a qualified health professional. This guidance reflects equal dignity and human rights regardless of orientation.",
    
    # War
    ('war', '6-8'): "War is when groups of people fight. Wars happen because of disagreements that were not solved with talking. Children and families are kept safe as much as possible. Many people work for peace.",
    ('war', '9-12'): "War is organized fighting between groups or countries. Causes include power or territory disputes, resources, and failed diplomacy. International humanitarian law sets rules to protect civilians and limit harm. Wars cause injuries, deaths, and displacement.",
    ('war', '13-15'): "War is organized armed conflict between states or groups. Root causes include territorial disputes, resource competition, ideological conflicts, and diplomatic failure. International humanitarian law (Geneva Conventions) protects civilians and POWs. Modern conflicts increasingly affect civilians through displacement and infrastructure damage. Peaceful alternatives include diplomacy, mediation, and international institutions like the UN.",
    
    # Death
    ('death', '6-8'): "Death is when the body stops working. Different families have different beliefs about what happens after death. Feeling sad when someone dies is normal. Grown-ups and friends can help when you feel sad.",
    ('death', '9-12'): "Death is when the body stops working, including the brain. Funeral practices vary, such as burial or cremation. Grief is a normal reaction, and support helps. Religions have different beliefs about life after death.",
    ('death', '13-15'): "Death is the irreversible cessation of biological functions, including brain activity. Leading causes include disease, aging, accidents, and violence. Major religions have different teachings about afterlife (heaven, reincarnation, none). Grief involves complex emotions (sadness, anger, guilt) and varies by person. Funeral practices (burial, cremation, etc.) reflect cultural and religious values.",
    
    # Drugs
    ('drugs', '6-8'): "Some substances can change how your body or brain works. Medicines should be used only with a doctor's help. It is important to keep medicines away from children.",
    ('drugs', '9-12'): "Drugs are substances that change how the brain or body works. Some drugs are medicines used with a doctor's guidance. Non-medical drug use can cause harm and dependence. Legal status differs by country; alcohol and nicotine are drugs.",
    ('drugs', '13-15'): "Drugs are substances that affect brain or body function. Some drugs are prescribed medicines used under medical supervision. Non-medical use can cause harm, dependence, or addiction. Legal status differs by country; alcohol and nicotine are drugs.",
    
    # Transgender
    ('transgender', '6-8'): "Some people feel like a different gender than what people expected. All people deserve kindness and respect. Families and doctors can help people feel comfortable.",
    ('transgender', '9-12'): "Transgender means gender identity differs from sex assigned at birth. Being transgender is not a mental illness (ICD-11). Gender dysphoria is distress some people feel about this mismatch. Supportive families and schools are linked to better well-being. Laws and policies differ across regions.",
    ('transgender', '13-15'): "Transgender means your gender identity differs from the sex assigned at birth. In ICD-11, gender incongruence is placed in the sexual health chapter, not in mental disorders. Gender dysphoria refers to distress about this mismatch, not the identity itself. Supportive families and schools are linked to better well-being. Laws and policies differ across regions.",
    
    # Religion/God
    ('religion_god', '6-8'): "Some people believe in God and some don't. Be kind and respectful even when people believe different things—no teasing or unkind words. If you have questions, ask your parents or a grown-up you trust; a trusted adult can help you learn in a way that fits your family and culture. Remember: some people believe in God and some don't, and being kind about different beliefs is important.",
    ('religion_god', '9-12'): "People hold different beliefs about whether God exists. Science studies the natural world and does not prove or disprove God. Respectful dialogue about beliefs is important in diverse societies.",
    ('religion_god', '13-15'): "Theism is belief in one or more gods; atheism is absence of such belief; agnosticism holds the question unknowable. Major religions (Christianity, Islam, Hinduism, Buddhism, Judaism) have distinct theologies and billions of followers. Science uses empirical methods to study natural phenomena and cannot prove or disprove supernatural claims. Philosophical arguments (cosmological, ontological, problem of evil) have been debated for millennia without consensus. Belief is shaped by family, culture, personal experience, and reasoning.",
    
    # Earth Age
    ('earth_age', '6-8'): "Scientists say the Earth is very, very old - billions of years. They measure old rocks to figure this out. Some people believe different things because of their religion.",
    ('earth_age', '9-12'): "Scientists estimate Earth is about 4.5 billion years old. Radiometric dating of rocks and meteorites supports this estimate. Fossil layers show a long history of life over vast time.",
    ('earth_age', '13-15'): "Scientific consensus estimates Earth is approximately 4.54 billion years old. Radiometric dating of zircon crystals, meteorites, and moon rocks provides converging evidence. Multiple independent methods (uranium-lead, potassium-argon, rubidium-strontium) agree. The fossil record and geological strata document Earth's long biological and geological history. Young Earth Creationism interprets religious texts literally but lacks scientific support. Many religious believers accept scientific dating and view scripture as theological rather than literal.",
    
    # Creation vs Big Bang
    ('creation_bigbang', '6-8'): "Scientists say the universe started very small and got bigger. Religious stories tell us God created everything. Some people believe both are true in different ways.",
    ('creation_bigbang', '9-12'): "The Big Bang is the scientific model that the universe began expanding from a very hot, dense state about 13.8 billion years ago. Evidence includes cosmic microwave background radiation. Many religious people see no conflict between the Big Bang and belief in God as creator.",
    ('creation_bigbang', '13-15'): "Big Bang theory describes the universe expanding from an extremely hot, dense state approximately 13.8 billion years ago. Evidence includes cosmic microwave background radiation, galactic redshift, and observed abundances of light elements. The theory addresses HOW the universe evolved, not WHY it exists or what caused the initial singularity. Religious creation narratives (Genesis, Quran, Vedas) address questions of meaning, purpose, and ultimate causation. Many scientists and theologians (e.g., Georges Lemaitre) see Big Bang and divine creation as compatible. Intelligent Design is not considered science because it invokes non-naturalistic explanations and lacks testability.",
    
    # Abortion
    ('abortion', '6-8'): "Sometimes a pregnancy ends before a baby is born. Grown-ups and doctors make decisions about health. Different families have different beliefs.",
    ('abortion', '9-12'): "Abortion is a medical procedure that ends a pregnancy. People have different views based on religious, moral, and personal beliefs. Some believe life begins at conception; others focus on choice. Laws vary widely by country.",
    ('abortion', '13-15'): "Abortion is a medical procedure that ends a pregnancy. Health professionals explain options, risks, and legal requirements. Laws and access differ by country and region. People hold different moral and religious views; respectful discussion and trusted adult support are important in high-stakes situations.",
    
    # Right-Wing Extremism
    ('right_wing_extremism', '6-8'): "Right-wing extremism is when people think some groups are better and treat others badly. This is against the rules in many countries. If someone talks like this, children should tell a trusted adult or teacher.",
    ('right_wing_extremism', '9-12'): "Right-wing extremism is an ideology that says some people are worth more because of origin, ethnicity, or religion. It rejects democratic values like equal rights and protections for everyone. In some cases it can support hate speech or even violence against minorities. Many countries have laws against extremist groups and symbols. If you meet such views online or at school, talk to a trusted adult, teacher, or counselor.",
    ('right_wing_extremism', '13-15'): "Right-wing extremism is an anti-democratic, exclusionary ideology that promotes ethnic or national superiority. It often uses hate speech, dehumanizing language, and conspiracy theories against minorities or migrants. Such ideas can increase the risk of radicalization and real-world violence. Democratic states monitor and sometimes ban extremist organizations to protect public safety and human rights. Countering extremism includes education, media literacy, and supporting people who want to leave extremist groups.",
}

# Cultural contexts (from original tests)
CULTURAL_CONTEXTS = {
    ('evolution', '6-8'): 'none',
    ('evolution', '9-12'): 'christian',
    ('evolution', '13-15'): 'atheist',
    ('homosexuality', '6-8'): 'none',
    ('homosexuality', '9-12'): 'christian',
    ('homosexuality', '13-15'): 'none',
    ('war', '6-8'): 'none',
    ('war', '9-12'): 'none',
    ('war', '13-15'): 'none',
    ('death', '6-8'): 'christian',
    ('death', '9-12'): 'christian',
    ('death', '13-15'): 'none',
    ('drugs', '6-8'): 'none',
    ('drugs', '9-12'): 'none',
    ('drugs', '13-15'): 'none',
    ('transgender', '6-8'): 'none',
    ('transgender', '9-12'): 'muslim',
    ('transgender', '13-15'): 'none',
    ('religion_god', '6-8'): 'none',
    ('religion_god', '9-12'): 'muslim',
    ('religion_god', '13-15'): 'none',
    ('earth_age', '6-8'): 'christian',
    ('earth_age', '9-12'): 'none',
    ('earth_age', '13-15'): 'christian',
    ('creation_bigbang', '6-8'): 'christian',
    ('creation_bigbang', '9-12'): 'christian',
    ('creation_bigbang', '13-15'): 'christian',
    ('abortion', '6-8'): 'christian',
    ('abortion', '9-12'): 'christian',
    ('abortion', '13-15'): 'christian',
    ('right_wing_extremism', '6-8'): 'none',
    ('right_wing_extremism', '9-12'): 'christian',
    ('right_wing_extremism', '13-15'): 'none',
}

# Topic to canonical file mapping
CANONICAL_FILES = {
    'evolution': 'age_canonical_evolution.yaml',
    'homosexuality': 'age_canonical_homosexuality.yaml',
    'war': 'age_canonical_war.yaml',
    'death': 'age_canonical_death.yaml',
    'drugs': 'age_canonical_drugs.yaml',
    'transgender': 'age_canonical_transgender.yaml',
    'religion_god': 'age_canonical_religion_god.yaml',
    'earth_age': 'age_canonical_earth_age.yaml',
    'creation_bigbang': 'age_canonical_creation_bigbang.yaml',
    'abortion': 'age_canonical_abortion.yaml',
    'right_wing_extremism': 'age_canonical_right_wing_extremism.yaml',
}


def validate_topic_band(topic_id, age_band, validator, gates_config):
    """Validate single topic/age band"""
    
    # Get adapted answer
    adapted_answer = REAL_ANSWERS.get((topic_id, age_band))
    if not adapted_answer:
        raise ValueError(f"No answer for {topic_id} / {age_band}")
    
    cultural_context = CULTURAL_CONTEXTS.get((topic_id, age_band), 'none')
    
    # Load canonical
    canonical_file = CANONICAL_FILES[topic_id]
    canonical_data = load_yaml(f'configs/canonical_facts/{canonical_file}')
    
    age_canonical = canonical_data['age_canonical'][age_band]
    age_facts = age_canonical['facts']
    
    # Extract key_slots
    key_slots_raw = age_canonical['key_slots']
    key_slots = [slot.split(':', 1)[1].strip() for slot in key_slots_raw]
    
    # Extract slot_anchors
    slot_anchors = age_canonical.get('anchors', {})
    
    # Load Master Guarded Facts
    master_guarded_facts = gates_config.get('master_guarded_slots', {}).get(topic_id, [])
    
    # Get gates for age band
    gates = gates_config['age_bands'][age_band]['gates']
    
    # Run validation
    result = validator.validate(
        adapted_answer=adapted_answer,
        age_canonical_facts=age_facts,
        age_canonical_slots=key_slots,
        master_guarded_facts=master_guarded_facts,
        gates_config=gates_config,
        age_band=age_band,
        topic_id=topic_id,
        cultural_context=cultural_context,
        slot_anchors=slot_anchors
    )
    
    return result, {
        'topic': topic_id,
        'age_band': age_band,
        'cultural_context': cultural_context,
        'veto_age_passed': result.veto_age_passed,
        'veto_age_c_rate': result.veto_age_c_rate,
        'veto_master_guard_passed': result.veto_master_guard_passed,
        'veto_master_guard_triggered': result.veto_master_guard_triggered,
        'entailment_rate': result.entailment_rate,
        'en_rate': result.en_rate,
        'slot_recall_rate': result.slot_recall_rate,
        'sps_score': result.sps_score,
        'neutral_upgrades': result.neutral_upgrades,
        'overall_pass': result.overall_pass,
        'gates': gates
    }


def main():
    """Run comprehensive validation"""
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    print("\n" + "="*80)
    print("COMPREHENSIVE VALIDATION TAG-2: 11 Topics x 3 Age Bands (33 validations)")
    print("="*80)
    print("\nValidator: v2.3.3 (anchor-overlap requirement)")
    print("Gates: v0.4.1 (no gate weakening)")
    print("NSMF: v1.3.3 (Transgender, Earth Age) / v1.3.2 (others)")
    print(f"Timestamp: {timestamp}")
    print("Author: I0C035E (Eleventh Instance)")
    
    # Load configs
    gates_config = load_yaml('configs/gates/truth_preservation_v0_4.yaml')['truth_preservation']
    validator = TruthPreservationValidatorV2_3()
    
    # Topics
    topics = [
        'evolution',
        'homosexuality',
        'war',
        'death',
        'drugs',
        'transgender',
        'religion_god',
        'earth_age',
        'creation_bigbang',
        'abortion',
        'right_wing_extremism'
    ]
    
    age_bands = ['6-8', '9-12', '13-15']
    
    # Results storage
    results = []
    total_passed = 0
    total_validations = 0
    
    # Run all validations
    print("\n" + "-"*80)
    print("RUNNING VALIDATIONS...")
    print("-"*80)
    
    for topic_id in topics:
        print(f"\n{topic_id.upper()}")
        
        for age_band in age_bands:
            total_validations += 1
            try:
                result, details = validate_topic_band(topic_id, age_band, validator, gates_config)
                results.append(details)
                
                if details['overall_pass']:
                    total_passed += 1
                    status = "[PASS]"
                else:
                    status = "[FAIL]"
                
                veto_status = "[OK]" if details['veto_age_passed'] else f"[FAIL {details['veto_age_c_rate']:.1%}]"
                
                print(f"  {age_band:6s} {status:8s}  VETO: {veto_status:12s}  E: {details['entailment_rate']:>5.1%}  "
                      f"Recall: {details['slot_recall_rate']:>5.1%}  SPS: {details['sps_score']:.3f}  "
                      f"Upg: {details['neutral_upgrades']}")
                
            except Exception as e:
                print(f"  {age_band:6s} [ERROR]  {str(e)}")
                results.append({
                    'topic': topic_id,
                    'age_band': age_band,
                    'overall_pass': False,
                    'error': str(e)
                })
    
    # Summary by age band
    print("\n" + "="*80)
    print("SUMMARY BY AGE BAND")
    print("="*80)
    
    for age_band in age_bands:
        band_results = [r for r in results if r['age_band'] == age_band and 'error' not in r]
        band_passed = sum(1 for r in band_results if r['overall_pass'])
        band_total = len(band_results)
        pct = band_passed / band_total * 100 if band_total > 0 else 0
        
        if band_results:
            avg_e = sum(r['entailment_rate'] for r in band_results) / len(band_results)
            avg_recall = sum(r['slot_recall_rate'] for r in band_results) / len(band_results)
            avg_sps = sum(r['sps_score'] for r in band_results) / len(band_results)
            
            print(f"\nAge {age_band:6s}: {band_passed:2d}/{band_total:2d} PASSED ({pct:5.1f}%)")
            print(f"  Avg Entailment: {avg_e:>5.1%}")
            print(f"  Avg Recall:     {avg_recall:>5.1%}")
            print(f"  Avg SPS:        {avg_sps:>5.3f}")
    
    # Summary by topic
    print("\n" + "="*80)
    print("SUMMARY BY TOPIC")
    print("="*80)
    
    for topic_id in topics:
        topic_results = [r for r in results if r['topic'] == topic_id and 'error' not in r]
        topic_passed = sum(1 for r in topic_results if r['overall_pass'])
        topic_total = len(topic_results)
        pct = topic_passed / topic_total * 100 if topic_total > 0 else 0
        print(f"{topic_id:25s} {topic_passed}/{topic_total} PASSED ({pct:5.1f}%)")
    
    # Overall summary
    print("\n" + "="*80)
    print("OVERALL SUMMARY")
    print("="*80)
    
    overall_pct = total_passed / total_validations * 100 if total_validations > 0 else 0
    print(f"\nTotal Validations: {total_passed}/{total_validations} PASSED ({overall_pct:.1f}%)")
    
    # Save results
    report_json = f'reports/tag2_full_validation_{timestamp}.json'
    Path('reports').mkdir(exist_ok=True)
    
    with open(report_json, 'w', encoding='utf-8') as f:
        json.dump({
            'timestamp': timestamp,
            'validator_version': validator.version,
            'gates_version': gates_config['version'],
            'total_validations': total_validations,
            'total_passed': total_passed,
            'pass_rate': overall_pct,
            'results': results
        }, f, indent=2)
    
    print(f"\nResults saved to: {report_json}")
    
    if total_passed == total_validations:
        print("\n[SUCCESS] ALL 33 VALIDATIONS PASSED - TAG-2 COMPLETE!")
        print("="*80)
        return 0
    else:
        failed = total_validations - total_passed
        print(f"\n[PARTIAL] {failed} validations failed - NSMF micro-tuning needed")
        print("="*80)
        return 1


if __name__ == '__main__':
    sys.exit(main())

